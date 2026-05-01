{$mode delphi}
unit LuaAI;

(* AI debugging co-pilot Lua module
   Exposes functions to gather debugging context and interact with AI APIs. *)

interface

uses
  Classes, SysUtils, lua, lauxlib, lualib, symbolhandlerstructs;

procedure initializeLuaAI;
function  buildContextString: string;
function  getProcessName: string;
procedure saveLLMSettings;

var
  g_apiKey: string;
  g_apiBaseUrl: string;
  g_apiModel: string;
  g_apiMaxTokens: integer;
  g_apiTemperature: double;

implementation

uses
  debughelper, ProcessHandlerUnit, debuggertypedefinitions, processlist,
  commontypedefs, NewKernelHandler, disassembler, symbolhandler,
  globals, debugeventhandler, breakpointtypedef,
  stacktrace2, LuaInternet, rescanhelper, LuaHandler,
  LCLProc, Windows, CEFuncProc, dialogs,
  contexthandler, LazUTF8, IniFiles,
  cesupport;

{-----------------------------------------------}
{ Global configuration }
{-----------------------------------------------}

var
  g_llmSettingsPath: string = '';

{-----------------------------------------------}
{ Helper: get settings path }
{-----------------------------------------------}

function getSettingsPath: string;
var
  appData: array[0..MAX_PATH] of Char;
  len: DWORD;
begin
  FillChar(appData, SizeOf(appData), 0);
  len := GetEnvironmentVariable('APPDATA', appData, Length(appData));
  if len > 0 then
    Result := string(appData)
  else
    Result := ExtractFilePath(ParamStr(0));
  Result := Result + 'Cheat Engine\LLMSettings.ini';
end;

procedure loadLLMSettings;
var
  ini: TIniFile;
begin
  g_llmSettingsPath := getSettingsPath;
  ini := TIniFile.Create(g_llmSettingsPath);
  try
    g_apiKey := ini.ReadString('LLM', 'APIKey', '');
    g_apiBaseUrl := ini.ReadString('LLM', 'BaseUrl', 'https://api.openai.com/v1/chat/completions');
    g_apiModel := ini.ReadString('LLM', 'Model', 'gpt-4o-mini');
    g_apiMaxTokens := ini.ReadInteger('LLM', 'MaxTokens', 2048);
    g_apiTemperature := ini.ReadFloat('LLM', 'Temperature', 0.2);
  finally
    ini.Free;
  end;
end;

procedure saveLLMSettings;
var
  ini: TIniFile;
begin
  if g_llmSettingsPath = '' then
    g_llmSettingsPath := getSettingsPath;
  ini := TIniFile.Create(g_llmSettingsPath);
  try
    ini.WriteString('LLM', 'APIKey', g_apiKey);
    ini.WriteString('LLM', 'BaseUrl', g_apiBaseUrl);
    ini.WriteString('LLM', 'Model', g_apiModel);
    ini.WriteInteger('LLM', 'MaxTokens', g_apiMaxTokens);
    ini.WriteFloat('LLM', 'Temperature', g_apiTemperature);
  finally
    ini.Free;
  end;
end;

{-----------------------------------------------}
{ Helper: safe string to Lua }
{-----------------------------------------------}

function safePushString(L: Plua_State; const s: string): integer;
begin
  if s = '' then
    lua_pushnil(L)
  else
    lua_pushstring(L, PChar(s));
  Result := 1;
end;

function luaToPtrUint(L: Plua_State; index: integer): ptruint;
begin
  Result := ptruint(lua_tointeger(L, index));
end;

{ lua_tostring returns PChar (AnsiString in FPC Lua bindings) }
function luaToString(L: Plua_State; index: integer): string;
var
  s: PChar;
begin
  s := PChar(lua_tostring(L, index));
  if s <> nil then
    Result := string(s)
  else
    Result := '';
end;

{-----------------------------------------------}
{ Helper: get current debug context + handler }
{-----------------------------------------------}

function getCurrentContext: pointer;
begin
  Result := nil;
  if (debuggerthread <> nil) and (debuggerthread.currentThread <> nil) then
    Result := debuggerthread.currentThread.context;
end;

function getContextHandler: TContextInfo;
begin
  Result := getBestContextHandler;
end;

{-----------------------------------------------}
{ Helper: get process name from handle }
{-----------------------------------------------}

function getProcessName: string;
var
  h: THandle;
  name: array[0..MAX_PATH] of Char;
  size: DWORD;
begin
  Result := 'None';
  if processhandler.processid = 0 then Exit;
  h := OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, processhandler.processid);
  if h <> 0 then
  try
    size := Length(name);
    if QueryFullProcessImageName(h, 0, name, @size) then
      Result := ExtractFileName(name)
    else
      Result := Format('Process_%d', [processhandler.processid]);
  finally
    CloseHandle(h);
  end;
end;

{-----------------------------------------------}
{ ai_readMemory - Read memory at address }
{-----------------------------------------------}

function ai_readMemory(L: Plua_State): integer; cdecl;
var
  addr: ptruint;
  size: integer;
  buf: array of byte;
  s: string;
  i: integer;
  actualread: SIZE_T;
begin
  Result := 0;
  try
    if lua_gettop(L) < 2 then
    begin
      lua_pushstring(L, 'Usage: ai_readMemory(address, size)');
      Exit;
    end;

    addr := luaToPtrUint(L, 1);
    size := lua_tointeger(L, 2);

    if size < 1 then size := 1;
    if size > 4096 then size := 4096;

    SetLength(buf, size);
    actualread := 0;
    if ReadProcessMemory(processhandle, pointer(addr), @buf[0], size, actualread) then
    begin
      s := '';
      for i := 0 to size - 1 do
        s := s + Format('%02X ', [buf[i]]);
      lua_pushstring(L, PChar(TrimRight(s)));
    end
    else
      lua_pushstring(L, '');

  except
    lua_pushstring(L, '');
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getRegisters - Get all register values }
{-----------------------------------------------}

function ai_getRegisters(L: Plua_State): integer; cdecl;
var
  ctx: pointer;
  ch: TContextInfo;
  gpr: PContextElementRegisterList;
  i: integer;
begin
  Result := 0;
  try
    ctx := getCurrentContext;
    if ctx = nil then
    begin
      lua_pushstring(L, 'No debug context available. Attach to a process first.');
      Exit;
    end;

    ch := getContextHandler;
    if ch = nil then
    begin
      lua_pushstring(L, 'Context handler not available.');
      Exit;
    end;

    gpr := ch.getGeneralPurposeRegisters;

    lua_newtable(L);
    if gpr <> nil then
      for i := 0 to length(gpr^) - 1 do
      begin
        lua_pushstring(L, PChar(gpr^[i].name));
        lua_pushinteger(L, gpr^[i].getValue(ctx));
        lua_settable(L, -3);
      end;

    lua_pushstring(L, 'architecture');
    if processhandler.is64bit then
      lua_pushstring(L, 'x64')
    else
      lua_pushstring(L, 'x86');
    lua_settable(L, -3);

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getCurrentRegister - Get RIP/EIP info }
{-----------------------------------------------}

function ai_getCurrentRegister(L: Plua_State): integer; cdecl;
var
  ctx: pointer;
  ch: TContextInfo;
  ipReg: PContextElement_register;
  ipAddr: ptruint;
  d: TDisassembler;
  desc: string;
begin
  Result := 0;
  try
    ctx := getCurrentContext;
    if ctx = nil then
    begin
      lua_pushstring(L, 'No debug context. Attach to a process first.');
      Exit;
    end;

    ch := getContextHandler;
    if ch = nil then
    begin
      lua_pushstring(L, 'Context handler not available.');
      Exit;
    end;

    ipReg := ch.InstructionPointerRegister;
    if ipReg = nil then
    begin
      lua_pushstring(L, 'Instruction pointer register not available.');
      Exit;
    end;

    ipAddr := ipReg.getValue(ctx);

    d := TDisassembler.Create;
    try
      desc := d.disassemble(ipAddr);
    finally
      d.Free;
    end;

    lua_newtable(L);
    lua_pushstring(L, 'name');
    lua_pushstring(L, PChar(ipReg.name));
    lua_settable(L, -3);

    lua_pushstring(L, 'value');
    lua_pushinteger(L, ipAddr);
    lua_settable(L, -3);

    lua_pushstring(L, 'disassembly');
    lua_pushstring(L, PChar(desc));
    lua_settable(L, -3);

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_disassemble - Disassemble at address }
{-----------------------------------------------}

function ai_disassemble(L: Plua_State): integer; cdecl;
var
  addr: ptruint;
  count: integer;
  d: TDisassembler;
  desc: string;
  i: integer;
begin
  Result := 0;
  try
    if lua_gettop(L) < 1 then
    begin
      lua_pushstring(L, 'Usage: ai_disassemble(address [, count])');
      Exit;
    end;

    addr := luaToPtrUint(L, 1);
    count := 5;
    if lua_gettop(L) >= 2 then
      count := lua_tointeger(L, 2);

    if count < 1 then count := 1;
    if count > 100 then count := 100;

    d := TDisassembler.Create;
    try
      lua_newtable(L);
      for i := 1 to count do
      begin
        desc := d.disassemble(addr);
        lua_pushinteger(L, i);
        lua_pushstring(L, PChar(desc));
        lua_settable(L, -3);
      end;
    finally
      d.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getThreadInfo - Get thread info }
{-----------------------------------------------}

function ai_getThreadInfo(L: Plua_State): integer; cdecl;
var
  tl: TList;
  i: integer;
  thread: TDebugThreadHandler;
begin
  Result := 0;
  try
    if (debuggerthread = nil) or (processhandler.processid = 0) then
    begin
      lua_pushstring(L, 'No process attached.');
      Exit;
    end;

    tl := debuggerthread.lockThreadlist;
    try
      lua_newtable(L);
      for i := 0 to tl.Count - 1 do
      begin
        thread := TDebugThreadHandler(tl[i]);
        lua_pushinteger(L, i + 1);
        lua_newtable(L);

        lua_pushstring(L, 'threadid');
        lua_pushinteger(L, thread.ThreadId);
        lua_settable(L, -3);

        lua_pushstring(L, 'isSuspended');
        lua_pushboolean(L, thread.isSuspended);
        lua_settable(L, -3);

        lua_pushstring(L, 'isWaitingToContinue');
        lua_pushboolean(L, thread.isWaitingToContinue);
        lua_settable(L, -3);

        lua_pushstring(L, 'isHandled');
        lua_pushboolean(L, thread.isHandled);
        lua_settable(L, -3);

        lua_settable(L, -3);
      end;
    finally
      debuggerthread.unlockThreadlist;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getBreakpoints - Get all breakpoints }
{-----------------------------------------------}

function ai_getBreakpoints(L: Plua_State): integer; cdecl;
var
  addrs: TAddressArray;
  i: integer;
  bp: PBreakpoint;
begin
  Result := 0;
  try
    if debuggerthread = nil then
    begin
      lua_pushstring(L, 'Debugger not available.');
      Exit;
    end;

    debuggerthread.getBreakpointAddresses(addrs);

    lua_newtable(L);
    for i := 0 to length(addrs) - 1 do
    begin
      bp := debuggerthread.isBreakpoint(addrs[i], 0, True);
      if bp <> nil then
      begin
        lua_pushinteger(L, i + 1);
        lua_newtable(L);

        lua_pushstring(L, 'address');
        lua_pushinteger(L, bp.address);
        lua_settable(L, -3);

        lua_pushstring(L, 'active');
        lua_pushboolean(L, bp.active);
        lua_settable(L, -3);

        lua_pushstring(L, 'size');
        lua_pushinteger(L, bp.size);
        lua_settable(L, -3);

        lua_pushstring(L, 'method');
        case bp.breakpointMethod of
          bpmInt3: lua_pushstring(L, 'int3');
          bpmDebugRegister: lua_pushstring(L, 'debugRegister');
          bpmException: lua_pushstring(L, 'exception');
          bpmDBVM: lua_pushstring(L, 'DBVM');
          bpmDBVMNative: lua_pushstring(L, 'DBVMNative');
          bpmGDB: lua_pushstring(L, 'GDB');
        else
          lua_pushstring(L, 'unknown');
        end;
        lua_settable(L, -3);

        lua_pushstring(L, 'trigger');
        case bp.breakpointTrigger of
          bptExecute: lua_pushstring(L, 'execute');
          bptAccess: lua_pushstring(L, 'access');
          bptWrite: lua_pushstring(L, 'write');
        else
          lua_pushstring(L, 'unknown');
        end;
        lua_settable(L, -3);

        lua_settable(L, -3);
      end;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getModuleList - Get loaded modules }
{-----------------------------------------------}

function ai_getModuleList(L: Plua_State): integer; cdecl;
var
  modList: TStringList;
  i: integer;
  name: string;
  mi: TModuleInfo;
begin
  Result := 0;
  try
    if processhandler.processid = 0 then
    begin
      lua_pushstring(L, 'No process attached.');
      Exit;
    end;

    modList := TStringList.Create;
    try
      symhandler.getModuleList(modList);
      lua_newtable(L);
      for i := 0 to modList.Count - 1 do
      begin
        name := modList[i];

        lua_pushinteger(L, i + 1);
        lua_newtable(L);

        lua_pushstring(L, 'name');
        lua_pushstring(L, PChar(name));
        lua_settable(L, -3);

        if symhandler.getmodulebyname(name, mi) then
        begin
          lua_pushstring(L, 'base');
          lua_pushinteger(L, mi.baseaddress);
          lua_settable(L, -3);

          lua_pushstring(L, 'size');
          lua_pushinteger(L, mi.basesize);
          lua_settable(L, -3);
        end;

        lua_settable(L, -3);
      end;
    finally
      modList.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getStackTrace - Get stack trace }
{-----------------------------------------------}

function ai_getStackTrace(L: Plua_State): integer; cdecl;
var
  ctx: pointer;
  j: integer;
  trace: TStringList;
  ch: TContextInfo;
  ipReg: PContextElement_register;
  espReg: PContextElement_register;
  ebpReg: PContextElement_register;
  eip: ptruint;
  esp: ptruint;
  ebp: ptruint;
begin
  Result := 0;
  try
    ctx := getCurrentContext;
    if ctx = nil then
    begin
      lua_pushstring(L, 'No debug context. Attach to a process first.');
      Exit;
    end;

    ch := getContextHandler;
    if ch = nil then
    begin
      lua_pushstring(L, 'Context handler not available.');
      Exit;
    end;

    { Get EIP, ESP, EBP from context }
    ipReg := ch.InstructionPointerRegister;
    espReg := ch.StackPointerRegister;
    ebpReg := ch.FramePointerRegister;

    if (ipReg = nil) or (espReg = nil) then
    begin
      lua_pushstring(L, 'Stack registers not available.');
      Exit;
    end;

    eip := ipReg.getValue(ctx);
    esp := espReg.getValue(ctx);
    if ebpReg <> nil then
      ebp := ebpReg.getValue(ctx)
    else
      ebp := 0;

    trace := TStringList.Create;
    try
      { ce_stacktrace(esp, ebp, eip, stack, size, trace, force4byte, showmodules, nosystem, maxdepth, refaddr, refname) }
      ce_stacktrace(esp, ebp, eip, nil, 0, trace, True, True, False, 50, 0, '');

      lua_newtable(L);
      for j := 0 to trace.Count - 1 do
      begin
        lua_pushinteger(L, j + 1);
        lua_pushstring(L, PChar(trace[j]));
        lua_settable(L, -3);
      end;
    finally
      trace.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getProcessInfo - Get process info }
{-----------------------------------------------}

function ai_getProcessInfo(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  try
    if processhandler.processid = 0 then
    begin
      lua_pushstring(L, 'No process attached.');
      Exit;
    end;

    lua_newtable(L);

    lua_pushstring(L, 'pid');
    lua_pushinteger(L, processhandler.processid);
    lua_settable(L, -3);

    lua_pushstring(L, 'name');
    lua_pushstring(L, PChar(getProcessName));
    lua_settable(L, -3);

    lua_pushstring(L, 'architecture');
    if processhandler.is64bit then
      lua_pushstring(L, 'x64')
    else
      lua_pushstring(L, 'x86');
    lua_settable(L, -3);

    lua_pushstring(L, 'bits');
    if processhandler.is64bit then
      lua_pushinteger(L, 64)
    else
      lua_pushinteger(L, 32);
    lua_settable(L, -3);

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_findPointer - Find pointer paths (stub) }
{-----------------------------------------------}

function ai_findPointer(L: Plua_State): integer; cdecl;
var
  addr: ptruint;
begin
  Result := 0;
  try
    if lua_gettop(L) < 1 then
    begin
      lua_pushstring(L, 'Usage: ai_findPointer(address)');
      Exit;
    end;

    addr := luaToPtrUint(L, 1);
    if processhandler.processid = 0 then
    begin
      lua_pushstring(L, 'No process attached.');
      Exit;
    end;

    { Pointer scanning is a complex GUI-driven feature in CE.
      Expose a Lua-level scan via rescanhelper instead. }
    lua_pushstring(L, PChar('Pointer scanning at 0x' + IntToHex(addr, 1) + '. Use the Pointer Scanner GUI for full functionality.'));

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getMemorySections - Get memory regions }
{-----------------------------------------------}

function ai_getMemorySections(L: Plua_State): integer; cdecl;
var
  helper: TRescanHelper;
  regions: TMemoryRegions;
  i: integer;
begin
  Result := 0;
  try
    if processhandler.processid = 0 then
    begin
      lua_pushstring(L, 'No process attached.');
      Exit;
    end;

    helper := TRescanHelper.Create;
    try
      regions := helper.getMemoryRegions;
      lua_newtable(L);
      for i := 0 to length(regions) - 1 do
      begin
        lua_pushinteger(L, i + 1);
        lua_newtable(L);

        lua_pushstring(L, 'start');
        lua_pushinteger(L, regions[i].BaseAddress);
        lua_settable(L, -3);

        lua_pushstring(L, 'size');
        lua_pushinteger(L, regions[i].MemorySize);
        lua_settable(L, -3);

        lua_pushstring(L, 'ischild');
        lua_pushboolean(L, regions[i].IsChild);
        lua_settable(L, -3);

        lua_settable(L, -3);
      end;
    finally
      helper.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ buildContextString - Comprehensive debug context }
{-----------------------------------------------}

function buildContextString: string;
var
  ctx: pointer;
  ch: TContextInfo;
  ipReg: PContextElement_register;
  ipAddr: ptruint;
  d: TDisassembler;
  regs: string;
  disasm: string;
  archStr: string;
  addrs: TAddressArray;
  gpr: PContextElementRegisterList;
  i: integer;
  bp: PBreakpoint;
  bpList: string;
  modList: TStringList;
  modListStr: string;
  thread: TDebugThreadHandler;
  tl: TList;
  threadStr: string;
  processName: string;
begin
  Result := '';
  regs := '';
  disasm := '';
  bpList := '';
  modListStr := '';
  threadStr := '';
  archStr := 'x86';

  ctx := getCurrentContext;
  ch := getContextHandler;

  if processhandler.processid <> 0 then
  begin
    if processhandler.is64bit then
      archStr := 'x64';
    processName := getProcessName;
  end
  else
    processName := 'None';

  if (ctx <> nil) and (ch <> nil) then
  begin
    { Registers }
    gpr := ch.getGeneralPurposeRegisters;
    if gpr <> nil then
      for i := 0 to length(gpr^) - 1 do
        regs := regs + Format('  %s: 0x%s%s', [gpr^[i].name, IntToHex(gpr^[i].getValue(ctx), 1), #13#10]);

    { Instruction pointer + disassembly }
    ipReg := ch.InstructionPointerRegister;
    if ipReg <> nil then
    begin
      ipAddr := ipReg.getValue(ctx);
      d := TDisassembler.Create;
      try
        disasm := '  ' + ipReg.name + ': 0x' + IntToHex(ipAddr, 1) + ' -> ' + d.disassemble(ipAddr) + #13#10;
      finally
        d.Free;
      end;
    end;
  end;

  { Breakpoints }
  if debuggerthread <> nil then
  begin
    debuggerthread.getBreakpointAddresses(addrs);
    for i := 0 to length(addrs) - 1 do
    begin
      bp := debuggerthread.isBreakpoint(addrs[i], 0, True);
      if bp <> nil then
        bpList := bpList + Format('  0x%s (active=%s)%s', [IntToHex(bp.address, 1), BoolToStr(bp.active, True), #13#10]);
    end;
  end;

  { Modules }
  if processhandler.processid <> 0 then
  begin
    modList := TStringList.Create;
    try
      symhandler.getModuleList(modList);
      for i := 0 to modList.Count - 1 do
        modListStr := modListStr + '  ' + modList[i] + #13#10;
    finally
      modList.Free;
    end;
  end;

  { Threads }
  if (debuggerthread <> nil) and (processhandler.processid <> 0) then
  begin
    tl := debuggerthread.lockThreadlist;
    try
      for i := 0 to tl.Count - 1 do
      begin
        thread := TDebugThreadHandler(tl[i]);
        threadStr := threadStr + Format('  Thread 0x%s (suspended=%s)%s', [IntToHex(thread.ThreadId, 1), BoolToStr(thread.isSuspended, True), #13#10]);
      end;
    finally
      debuggerthread.unlockThreadlist;
    end;
  end;

  Result := Format(
    'Process: %s (PID: %d, Arch: %s)%s' +
    'Registers:%s%s' +
    'Disassembly:%s%s' +
    'Breakpoints:%s%s' +
    'Modules:%s%s' +
    'Threads:%s%s',
    [processName, processhandler.processid, archStr, #13#10,
     #13#10, regs, #13#10, disasm, #13#10, #13#10, bpList, #13#10,
     #13#10, modListStr, #13#10, #13#10, threadStr]);
end;

{-----------------------------------------------}
{ ai_gatherContext - Comprehensive debug context }
{-----------------------------------------------}

function ai_gatherContext(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  lua_pushstring(L, PChar(buildContextString));
end;

{-----------------------------------------------}
{ ai_call - HTTP POST call to AI API }
{-----------------------------------------------}

function ai_call(L: Plua_State): integer; cdecl;
var
  url: string;
  body: string;
  http: TWinInternet;
  memStream: TMemoryStream;
  response: AnsiString;
begin
  Result := 0;
  try
    if lua_gettop(L) < 2 then
    begin
      lua_pushstring(L, 'Usage: ai_call(url, body)');
      Exit;
    end;

    url := luaToString(L, 1);
    body := luaToString(L, 2);

    http := TWinInternet.Create('AI');
    try
      http.Header := 'Content-Type: application/json';
      memStream := TMemoryStream.Create;
      try
        http.postURL(url, body, memStream);
        memStream.Position := 0;
        SetLength(response, memStream.Size);
        if memStream.Size > 0 then
          memStream.Read(PAnsiChar(response)^, memStream.Size);
        lua_pushstring(L, PChar(response));
      finally
        memStream.Free;
      end;
    finally
      http.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_setKey - Set API key }
{-----------------------------------------------}

function ai_setKey(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  if lua_gettop(L) < 1 then
  begin
    lua_pushstring(L, 'Usage: ai_setKey("your-api-key")');
    Exit;
  end;
  g_apiKey := luaToString(L, 1);
  saveLLMSettings;
  lua_pushnil(L);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getKey - Get API key }
{-----------------------------------------------}

function ai_getKey(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  lua_pushstring(L, PChar(g_apiKey));
  Result := 1;
end;

{-----------------------------------------------}
{ ai_setBaseUrl - Set API base URL }
{-----------------------------------------------}

function ai_setBaseUrl(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  if lua_gettop(L) < 1 then
  begin
    lua_pushstring(L, 'Usage: ai_setBaseUrl("https://api.openai.com/v1/chat/completions")');
    Exit;
  end;
  g_apiBaseUrl := luaToString(L, 1);
  saveLLMSettings;
  lua_pushnil(L);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getBaseUrl - Get base URL }
{-----------------------------------------------}

function ai_getBaseUrl(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  lua_pushstring(L, PChar(g_apiBaseUrl));
  Result := 1;
end;

{-----------------------------------------------}
{ ai_setModel - Set AI model name }
{-----------------------------------------------}

function ai_setModel(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  if lua_gettop(L) < 1 then
  begin
    lua_pushstring(L, 'Usage: ai_setModel("gpt-4o")');
    Exit;
  end;
  g_apiModel := luaToString(L, 1);
  saveLLMSettings;
  lua_pushnil(L);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getModel - Get model name }
{-----------------------------------------------}

function ai_getModel(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  lua_pushstring(L, PChar(g_apiModel));
  Result := 1;
end;

{-----------------------------------------------}
{ ai_setMaxTokens - Set max tokens }
{-----------------------------------------------}

function ai_setMaxTokens(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  if lua_gettop(L) < 1 then
  begin
    lua_pushstring(L, 'Usage: ai_setMaxTokens(2048)');
    Exit;
  end;
  g_apiMaxTokens := lua_tointeger(L, 1);
  saveLLMSettings;
  lua_pushnil(L);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getMaxTokens - Get max tokens }
{-----------------------------------------------}

function ai_getMaxTokens(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  lua_pushinteger(L, g_apiMaxTokens);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_setTemperature - Set temperature }
{-----------------------------------------------}

function ai_setTemperature(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  if lua_gettop(L) < 1 then
  begin
    lua_pushstring(L, 'Usage: ai_setTemperature(0.2)');
    Exit;
  end;
  g_apiTemperature := lua_tonumber(L, 1);
  saveLLMSettings;
  lua_pushnil(L);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_getTemperature - Get temperature }
{-----------------------------------------------}

function ai_getTemperature(L: Plua_State): integer; cdecl;
begin
  Result := 0;
  lua_pushnumber(L, g_apiTemperature);
  Result := 1;
end;

{-----------------------------------------------}
{ ai_chat - Conversational AI (sends context + message) }
{-----------------------------------------------}

function ai_chat(L: Plua_State): integer; cdecl;
var
  message: string;
  contextStr: string;
  jsonBody: string;
  response: AnsiString;
  http: TWinInternet;
  postResult: boolean;
  memStream: TMemoryStream;
  escapedMessage: string;
  authHeader: AnsiString;
  systemPrompt: AnsiString;
  jsonMsgs: AnsiString;
begin
  Result := 0;
  try
    if lua_gettop(L) < 1 then
    begin
      lua_pushstring(L, 'Usage: ai_chat(message)');
      Exit;
    end;

    if g_apiKey = '' then
    begin
      lua_pushstring(L, 'No API key set. Use ai_setKey("your-key") or Tools > AI Chat > LLM Settings.');
      Exit;
    end;

    message := luaToString(L, 1);
    contextStr := buildContextString;

    systemPrompt := 'You are an expert reverse engineering assistant embedded in Cheat Engine. ' +
      'You help analyze debugged processes, disassembly, and memory. ' +
      'The current debug context is:' + #13#10 + #13#10 +
      contextStr + #13#10 +
      'Be concise and technical. Use hex addresses where relevant.';

    { Build JSON body using AnsiString for UTF-8 safety }
    jsonMsgs := Format(
      '{"model":"%s","temperature":%.2f,"max_tokens":%d,"messages":[{"role":"system","content":"%s"},{"role":"user","content":"%s"}]}',
      [g_apiModel, g_apiTemperature, g_apiMaxTokens,
       AnsiString(systemPrompt), AnsiString(message)]);

    authHeader := AnsiString('Authorization: Bearer ' + g_apiKey);

    http := TWinInternet.Create('AI');
    try
      http.Header := authHeader + #13#10 + 'Content-Type: application/json';
      memStream := TMemoryStream.Create;
      try
        postResult := http.postURL(g_apiBaseUrl, AnsiString(jsonMsgs), memStream);
        if postResult then
        begin
          memStream.Position := 0;
          SetLength(response, memStream.Size);
          if memStream.Size > 0 then
            memStream.Read(PAnsiChar(response)^, memStream.Size);
          lua_pushstring(L, PChar(response));
        end
        else
          lua_pushstring(L, 'Request failed');
      finally
        memStream.Free;
      end;
    finally
      http.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_chatStream - Streaming AI response }
{-----------------------------------------------}

function ai_chatStream(L: Plua_State): integer; cdecl;
var
  message: string;
begin
  Result := 0;
  try
    if lua_gettop(L) < 1 then
    begin
      lua_pushstring(L, 'Usage: ai_chatStream(message)');
      Exit;
    end;
    if g_apiKey = '' then
    begin
      lua_pushstring(L, 'No API key set. Use ai_setKey("your-key") first.');
      Exit;
    end;
    message := luaToString(L, 1);
    lua_pushstring(L, PChar('Streaming not yet implemented. Use ai_chat() instead.'));
  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ ai_testConnection - Test LLM endpoint }
{-----------------------------------------------}

function ai_testConnection(L: Plua_State): integer; cdecl;
var
  http: TWinInternet;
  memStream: TMemoryStream;
  response: AnsiString;
  baseUrl: string;
  authHeader: AnsiString;
begin
  Result := 0;
  try
    baseUrl := g_apiBaseUrl;
    if lua_gettop(L) >= 1 then
      baseUrl := luaToString(L, 1);

    http := TWinInternet.Create('AI');
    try
      authHeader := 'Content-Type: application/json';
      if g_apiKey <> '' then
        authHeader := AnsiString('Authorization: Bearer ' + g_apiKey) + #13#10 + authHeader;
      http.Header := authHeader;

      memStream := TMemoryStream.Create;
      try
        if http.postURL(baseUrl, '{"model":"test"}', memStream) then
        begin
          memStream.Position := 0;
          SetLength(response, memStream.Size);
          if memStream.Size > 0 then
            memStream.Read(PAnsiChar(response)^, memStream.Size);
          lua_pushstring(L, PChar('Connected: ' + Copy(response, 1, 200)));
        end
        else
          lua_pushstring(L, 'Connection failed');
      finally
        memStream.Free;
      end;
    finally
      http.Free;
    end;

  except
    on e: Exception do
    begin
      lua_pushstring(L, PChar('Error: ' + e.Message));
    end;
  end;
  Result := 1;
end;

{-----------------------------------------------}
{ registerLuaAI - Register all AI functions }
{-----------------------------------------------}

procedure initializeLuaAI;
begin
  loadLLMSettings;
  lua_register(LuaVM, 'ai_readMemory', ai_readMemory);
  lua_register(LuaVM, 'ai_getRegisters', ai_getRegisters);
  lua_register(LuaVM, 'ai_getCurrentRegister', ai_getCurrentRegister);
  lua_register(LuaVM, 'ai_disassemble', ai_disassemble);
  lua_register(LuaVM, 'ai_getThreadInfo', ai_getThreadInfo);
  lua_register(LuaVM, 'ai_getBreakpoints', ai_getBreakpoints);
  lua_register(LuaVM, 'ai_getModuleList', ai_getModuleList);
  lua_register(LuaVM, 'ai_getStackTrace', ai_getStackTrace);
  lua_register(LuaVM, 'ai_getProcessInfo', ai_getProcessInfo);
  lua_register(LuaVM, 'ai_findPointer', ai_findPointer);
  lua_register(LuaVM, 'ai_getMemorySections', ai_getMemorySections);
  lua_register(LuaVM, 'ai_gatherContext', ai_gatherContext);
  lua_register(LuaVM, 'ai_call', ai_call);
  lua_register(LuaVM, 'ai_setKey', ai_setKey);
  lua_register(LuaVM, 'ai_getKey', ai_getKey);
  lua_register(LuaVM, 'ai_setBaseUrl', ai_setBaseUrl);
  lua_register(LuaVM, 'ai_getBaseUrl', ai_getBaseUrl);
  lua_register(LuaVM, 'ai_setModel', ai_setModel);
  lua_register(LuaVM, 'ai_getModel', ai_getModel);
  lua_register(LuaVM, 'ai_setMaxTokens', ai_setMaxTokens);
  lua_register(LuaVM, 'ai_getMaxTokens', ai_getMaxTokens);
  lua_register(LuaVM, 'ai_setTemperature', ai_setTemperature);
  lua_register(LuaVM, 'ai_getTemperature', ai_getTemperature);
  lua_register(LuaVM, 'ai_chat', ai_chat);
  lua_register(LuaVM, 'ai_chatStream', ai_chatStream);
  lua_register(LuaVM, 'ai_testConnection', ai_testConnection);
end;

end.
