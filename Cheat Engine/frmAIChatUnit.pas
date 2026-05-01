unit frmAIChatUnit;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ExtCtrls,
  Buttons, ComCtrls, LCLIntf, LCLType, Registry, LuaHandler,
  LuaInternet, ProcessHandlerUnit, debughelper, disassembler, symbolhandler,
  symbolhandlerstructs, globals, LuaAI, contexthandler, StrUtils,
  commontypedefs, breakpointtypedef, Windows;

type
  TfrmAIChat = class(TForm)
    PanelTop: TPanel;
    MemoChat: TMemo;
    Splitter1: TSplitter;
    PanelBottom: TPanel;
    MemoInput: TMemo;
    PanelButtons: TPanel;
    btnSend: TButton;
    btnContext: TButton;
    btnClear: TButton;
    btnSettings: TButton;
    LabelStatus: TLabel;
    chkIncludeContext: TCheckBox;
    Timer1: TTimer;
    procedure FormCreate(Sender: TObject);
    procedure FormDestroy(Sender: TObject);
    procedure btnSendClick(Sender: TObject);
    procedure btnContextClick(Sender: TObject);
    procedure btnClearClick(Sender: TObject);
    procedure btnSettingsClick(Sender: TObject);
    procedure MemoInputKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
    procedure Timer1Timer(Sender: TObject);
  private
    FAPIKey: string;
    FAPIUrl: string;
    FModel: string;
    FHistory: TStringList;
    FIsSending: Boolean;
    procedure LoadSettings;
    procedure SaveSettings;
    procedure AddMessage(const ASender, AText: string);
    procedure DoSendToAPI;
    function GatherDebugContext: string;
    procedure UpdateDebugState;
  public
    procedure OnBreakpoint;
  end;

var
  frmAIChat: TfrmAIChat;

implementation

{$R *.lfm}

{ TfrmAIChat }

procedure TfrmAIChat.FormCreate(Sender: TObject);
begin
  FHistory := TStringList.Create;
  FIsSending := False;
  LoadSettings;
  UpdateDebugState;

  MemoChat.ScrollBars := ssVertical;
  MemoChat.ReadOnly := True;
  MemoChat.Font.Name := 'Consolas';
  MemoChat.Font.Size := 10;

  MemoInput.ScrollBars := ssVertical;
  MemoInput.Font.Name := 'Consolas';
  MemoInput.Font.Size := 10;

  Timer1.Interval := 2000;
  Timer1.Enabled := True;

  AddMessage('System', 'AI Chat initialized. Set API key with ai_setKey("key") or via Settings.');
end;

procedure TfrmAIChat.FormDestroy(Sender: TObject);
begin
  FHistory.Free;
end;

procedure TfrmAIChat.LoadSettings;
var
  reg: TRegistry;
begin
  reg := TRegistry.Create;
  reg.RootKey := HKEY_CURRENT_USER;
  reg.LazyWrite := False;
  try
    if reg.OpenKey('Software\Cheat Engine\AI', False) then
    begin
      FAPIKey := '';
      FAPIUrl := 'https://api.openai.com/v1/chat/completions';
      FModel := 'gpt-4o-mini';
      if reg.ValueExists('APIKey') then
        FAPIKey := reg.ReadString('APIKey');
      if reg.ValueExists('APIUrl') then
        FAPIUrl := reg.ReadString('APIUrl');
      if reg.ValueExists('Model') then
        FModel := reg.ReadString('Model');
    end;
  finally
    reg.Free;
  end;
end;

procedure TfrmAIChat.SaveSettings;
var
  reg: TRegistry;
begin
  reg := TRegistry.Create;
  reg.RootKey := HKEY_CURRENT_USER;
  reg.LazyWrite := False;
  try
    if reg.OpenKey('Software\Cheat Engine\AI', True) then
    begin
      reg.WriteString('APIKey', FAPIKey);
      reg.WriteString('APIUrl', FAPIUrl);
      reg.WriteString('Model', FModel);
    end;
  finally
    reg.Free;
  end;
end;

procedure TfrmAIChat.AddMessage(const ASender, AText: string);
begin
  MemoChat.Lines.Add('[' + ASender + ']: ' + AText);
  MemoChat.Lines.Add('');
  MemoChat.Lines.Add('');
  SendMessage(MemoChat.Handle, WM_VSCROLL, SB_BOTTOM, 0);
end;

function TfrmAIChat.GatherDebugContext: string;
var
  ctx: pointer;
  ch: TContextInfo;
  ipReg: PContextElement_register;
  ipAddr: ptruint;
  d: TDisassembler;
  s: TStringList;
  gpr: PContextElementRegisterList;
  regEntry: TContextElement_register;
  i, j: integer;
  addrs: TAddressArray;
  bp: PBreakpoint;
  curAddr: ptruint;
  modList: TStringList;
  mi: TModuleInfo;
begin
  s := TStringList.Create;
  try
    s.Add('=== DEBUG CONTEXT ===');
    s.Add('');

    { Process info }
    s.Add('Process: ' + getProcessName + ' (PID: ' + IntToStr(processhandler.processid) + ')');
    if processhandler.is64bit then
      s.Add('Architecture: x64')
    else
      s.Add('Architecture: x86');
    if debuggerthread <> nil then
      s.Add('Debug State: attached')
    else
      s.Add('Debug State: detached');
    s.Add('');

    { Registers }
    s.Add('--- REGISTERS ---');
    ctx := nil;
    if (debuggerthread <> nil) and (debuggerthread.currentThread <> nil) then
      ctx := debuggerthread.currentThread.context;

    if ctx <> nil then
    begin
      ch := getBestContextHandler;
      if ch <> nil then
      begin
        gpr := ch.getGeneralPurposeRegisters;
     for i := 0 to length(gpr^) - 1 do
        begin
          regEntry := gpr^[i];
          s.Add(Format('  %s: 0x%s', [regEntry.name, IntToHex(regEntry.getValue(ctx), 1)]));
        end;

        { Disassembly at IP }
        ipReg := ch.InstructionPointerRegister;
        if ipReg <> nil then
        begin
     ipAddr := ipReg^.getValue(ctx);
        s.Add('');
        s.Add('--- DISASSEMBLY (at ' + ipReg^.name + ': 0x' + IntToHex(ipAddr, 1) + ') ---');
        d := TDisassembler.Create;
        try
          curAddr := ipAddr;
          for j := 0 to 9 do
          begin
            s.Add(Format('  0x%s: %s', [IntToHex(curAddr, 1), d.disassemble(curAddr)]));
          end;
        finally
          d.Free;
        end;
      end;
      end;
    end
    else
      s.Add('  (not broken - no register info)');

    { Breakpoints }
    s.Add('');
    s.Add('--- BREAKPOINTS ---');
    if debuggerthread <> nil then
    begin
      debuggerthread.getBreakpointAddresses(addrs);
      if length(addrs) > 0 then
      begin
        for i := 0 to length(addrs) - 1 do
        begin
          bp := debuggerthread.isBreakpoint(addrs[i], 0, True);
          if bp <> nil then
            s.Add(Format('  0x%s active=%s', [IntToHex(bp^.address, 1), BoolToStr(bp^.active, True)]));
        end;
      end
      else
        s.Add('  (none)');
    end;

    { Modules }
    s.Add('');
    s.Add('--- MODULES ---');
    modList := TStringList.Create;
    try
      symhandler.getModuleList(modList);
      for i := 0 to modList.Count - 1 do
      begin
        if symhandler.getmodulebyname(modList[i], mi) then
          s.Add(Format('  %s: 0x%s (%s bytes)',
            [mi.modulename, IntToHex(mi.baseaddress, 1), IntToStr(mi.basesize)]))
        else
          s.Add('  ' + modList[i]);
      end;
    finally
      modList.Free;
    end;

    Result := s.Text;
  finally
    s.Free;
  end;
end;

procedure TfrmAIChat.DoSendToAPI;
var
  query: string;
  jsonBody: string;
  systemPrompt: string;
  response: AnsiString;
  contextStr: string;
  memStream: TMemoryStream;
  http: TWinInternet;
  contentStart: integer;
  content: string;
  quotePos: integer;
begin
  if FIsSending then Exit;
  FIsSending := True;
  btnSend.Enabled := False;
  LabelStatus.Caption := 'Sending...';
  Application.ProcessMessages;

  try
    query := MemoInput.Text;
    if query = '' then
    begin
      AddMessage('Error', 'Please enter a message.');
      Exit;
    end;

    AddMessage('You', query);
    MemoInput.Clear;

    if chkIncludeContext.Checked then
      contextStr := GatherDebugContext
    else
      contextStr := '(no context included)';

    systemPrompt := 'You are an expert reverse engineering assistant embedded in Cheat Engine. ' +
      'You help analyze debugged processes, disassembly, and memory. ' +
      'The current debug context is: ' + #13#10 + #13#10 +
      contextStr + #13#10 +
      'Be concise and technical. Use hex addresses where relevant.';

    jsonBody := Format(
      '{"model":"%s","temperature":0.2,"max_tokens":2048,"messages":[{"role":"system","content":%s},{"role":"user","content":%s}]}',
      [FModel, AnsiQuotedStr(systemPrompt, '"'), AnsiQuotedStr(query, '"')]
    );

    http := TWinInternet.Create('AIChat');
    memStream := TMemoryStream.Create;
    try
      http.Header := 'Content-Type: application/json' + #13#10;
     if FAPIKey <> '' then
        http.Header := http.Header + 'Authorization: Bearer ' + FAPIKey + #13#10;

      if http.postURL(FAPIUrl, jsonBody, memStream) then
      begin
        memStream.Position := 0;
        SetLength(response, memStream.Size);
        if memStream.Size > 0 then
          memStream.Read(PAnsiChar(response)^, memStream.Size);
      end
      else
        response := '';

      if response <> '' then
      begin
        try
          { Extract the actual content from the JSON response }
          contentStart := Pos('"content":', string(response));
          if contentStart > 0 then
          begin
            content := Copy(string(response), contentStart + 10, Length(string(response)));
            quotePos := Pos('"', content);
            if quotePos > 0 then
              content := Copy(content, quotePos + 1, Length(content) - quotePos - 1);
            { Handle escaped newlines }
            content := StringReplace(content, '\n', #13#10, [rfReplaceAll]);
            content := StringReplace(content, '\t', '  ', [rfReplaceAll]);
            AddMessage('AI', content);
          end
          else
            AddMessage('AI', string(response));
        except
          AddMessage('AI', string(response));
        end;
      end
      else
        AddMessage('Error', 'Empty or failed response from API.');

    finally
      memStream.Free;
      http.Free;
    end;

  except
    on E: Exception do
      AddMessage('Error', E.Message);
  end;

  FIsSending := False;
  btnSend.Enabled := True;
  LabelStatus.Caption := 'Ready';
end;

procedure TfrmAIChat.btnSendClick(Sender: TObject);
begin
  DoSendToAPI;
end;

procedure TfrmAIChat.btnContextClick(Sender: TObject);
var
  context: string;
begin
  context := GatherDebugContext;
  AddMessage('Context', context);
end;

procedure TfrmAIChat.btnClearClick(Sender: TObject);
begin
  MemoChat.Lines.Clear;
  FHistory.Clear;
  AddMessage('System', 'Chat cleared.');
end;

procedure TfrmAIChat.btnSettingsClick(Sender: TObject);
var
  s: string;
begin
  s := InputBox('AI Settings', 'API URL:', FAPIUrl);
  if s <> '' then FAPIUrl := s;

  s := InputBox('AI Settings', 'Model:', FModel);
  if s <> '' then FModel := s;

  s := InputBox('AI Settings', 'API Key (leave blank to clear):', FAPIKey);
  FAPIKey := s;

  SaveSettings;
  AddMessage('System', Format('Settings saved. URL: %s, Model: %s, Key: %s',
    [FAPIUrl, FModel, IfThen(FAPIKey <> '', '(set)', '(empty)')]));
end;

procedure TfrmAIChat.MemoInputKeyDown(Sender: TObject; var Key: Word; Shift: TShiftState);
begin
  if (Key = VK_RETURN) and (ssCtrl in Shift) then
  begin
    btnSendClick(Sender);
    Key := 0;
  end;
end;

procedure TfrmAIChat.Timer1Timer(Sender: TObject);
begin
  UpdateDebugState;
end;

procedure TfrmAIChat.UpdateDebugState;
var
  state: string;
begin
  if (debuggerthread <> nil) and (processhandler.processid <> 0) then
  begin
    state := 'RUNNING';
    if debuggerthread.isWaitingToContinue then state := 'BROKEN';
    LabelStatus.Caption := Format('Debugging: %s (PID: %d) - %s',
      [getProcessName, processhandler.processid, state]);
  end
  else
  begin
    LabelStatus.Caption := 'Not debugging';
  end;
end;

procedure TfrmAIChat.OnBreakpoint;
begin
  AddMessage('System', 'Breakpoint hit! Debug context updated.');
  UpdateDebugState;
end;

end.
