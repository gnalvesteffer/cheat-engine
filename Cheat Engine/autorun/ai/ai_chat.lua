-- Cheat Engine AI Chat Integration
-- Auto-loads on CE startup. Works with any CE 7.x binary (no custom build needed).
--
-- Features:
--   * AI chat with full debug context (process, registers, disassembly, breakpoints, modules)
--   * Chat window using CE's Lua GUI API
--   * Exposes debugging tools to AI for analysis
--   * Executes AI-suggested Lua code (sandboxed with pcall)
--
-- Configuration (environment variables or edit directly):
--   AI_API_ENDPOINT  - OpenAI-compatible API URL (default: http://localhost:11434/v1/chat/completions)
--   AI_MODEL         - Model name (default: qwen3:32b)
--   AI_API_KEY       - API key for OpenAI-compatible APIs
--
-- Usage:
--   1. Open Cheat Engine with a target process
--   2. Tools -> AI Chat (or Ctrl+Shift+A)
--   3. Type questions about memory, disassembly, game mechanics, etc.
--   4. AI can suggest Auto Assembler scripts or Lua code
--   5. Use "Execute Code" button to run AI-suggested code

ceai = {
  endpoint = os.getenv("AI_API_ENDPOINT") or "http://localhost:11434/v1/chat/completions",
  model = os.getenv("AI_MODEL") or "qwen3:32b",
  api_key = os.getenv("AI_API_KEY") or "",
  timeout = 30000,
  -- Internal state
  chatForm = nil,
  chatMemo = nil,
  inputMemo = nil,
  lastAIResponse = "",
  isSending = false,
}

-- ============================================================
-- Utility
-- ============================================================

function ceai.escapeJson(s)
  s = string.gsub(s, '\\', '\\\\')
  s = string.gsub(s, '"', '\\"')
  s = string.gsub(s, '\n', '\\n')
  s = string.gsub(s, '\r', '\\r')
  s = string.gsub(s, '\t', '\\t')
  return s
end

-- ============================================================
-- Debug Context Gathering
-- ============================================================

function ceai.getProcessInfo()
  local pid = getOpenedProcessID()
  if pid == 0 then return nil end
  local name = ""
  try
    name = getProcessNameFromProcessID(pid) or ""
  catch
  end
  return {
    pid = pid,
    name = name,
    bits = is64Bit() and "x64" or "x86",
  }
end

function ceai.getAddressList()
  local al = getAddressList()
  local addrs = {}
  for i = 0, al.Count - 1 do
    local mr = al.MemoryRecord[i]
    addrs[#addrs + 1] = {
      name = mr.Description,
      address = mr.Address,
      type = mr.VTName,
      value = mr.CurrentValue,
      frozen = mr.Frozen and "true" or "false",
    }
  end
  return addrs
end

function ceai.getDisassembly(address, count)
  count = count or 10
  local lines = {}
  local addr = address
  for i = 1, count do
    try
      local disasm = getDisasmEx(addr, 1)
      if disasm then
        local hex = string.format("%X", addr)
        lines[#lines + 1] = string.format("  0x%s: %s", hex, disasm)
      end
      local instrSize = getInstructionSize(addr)
      if instrSize and instrSize > 0 then
        addr = addr + instrSize
      else
        break
      end
    catch
      break
    end
  end
  return table.concat(lines, "\n")
end

function ceai.getRegisters()
  if getOpenedProcessID() == 0 or not isDebugging() then
    return "  Not debugging"
  end
  local regs = {}
  regs["EAX"] = string.format("0x%08X", getEAX())
  regs["EBX"] = string.format("0x%08X", getEBX())
  regs["ECX"] = string.format("0x%08X", getECX())
  regs["EDX"] = string.format("0x%08X", getEDX())
  regs["ESI"] = string.format("0x%08X", getESI())
  regs["EDI"] = string.format("0x%08X", getEDI())
  regs["ESP"] = string.format("0x%08X", getESP())
  regs["EBP"] = string.format("0x%08X", getEBP())
  regs["EIP"] = string.format("0x%08X", getEIP())
  regs["EFlags"] = string.format("0x%08X", getEFlags())
  return table.concat(regs, "\n")
end

function ceai.getBreakpoints()
  if not isDebugging() then return "  Not debugging" end
  local bps = {}
  local addrs = {}
  try
    -- Get breakpoint list from debugger thread
    addrs = getBreakpointAddresses() or {}
  catch
  end
  if #addrs == 0 then return "  (none)" end
  for _, addr in ipairs(addrs) do
    bps[#bps + 1] = string.format("  0x%X", addr)
  end
  return table.concat(bps, "\n")
end

function ceai.getModules()
  if getOpenedProcessID() == 0 then return "  No process opened" end
  local mods = {}
  local modList = getModuleList()
  if not modList then return "  Could not read module list" end
  for i, mod in ipairs(modList) do
    mods[#mods + 1] = string.format("  %s: 0x%X (%d bytes)",
      mod.Name or "?", mod.BaseAddress or 0, mod.Size or 0)
  end
  if #mods == 0 then return "  (none)" end
  return table.concat(mods, "\n")
end

function ceai.getStackTrace()
  if not isDebugging() then return "  Not debugging" end
  local stack = {}
  local ebp = getEBP()
  local frameCount = 0
  local maxFrames = 20
  while ebp and ebp > 0 and frameCount < maxFrames do
    local eip = 0
    try
      eip = readInteger(ebp + 4) or 0
    catch
      break
    end
    if eip == 0 then break end
    local modInfo = ""
    try
      modInfo = getModuleNameFromAddress(eip) or "<unknown>"
    catch
      modInfo = "<unknown>"
    end
    stack[#stack + 1] = string.format("  #%d: 0x%X (%s)",
      frameCount, eip, modInfo)
    ebp = 0
    try
      ebp = readInteger(ebp) or 0
    catch
      break
    end
    frameCount = frameCount + 1
  end
  return table.concat(stack, "\n")
end

-- Build comprehensive debug context string
function ceai.gatherContext()
  local lines = {}
  local proc = ceai.getProcessInfo()
  if proc then
    table.insert(lines, "=== PROCESS ===")
    table.insert(lines, string.format("PID: %d, Name: %s, Arch: %s",
      proc.pid, proc.name, proc.bits))
    table.insert(lines, "")
  end

  table.insert(lines, "=== REGISTERS ===")
  table.insert(lines, ceai.getRegisters())
  table.insert(lines, "")

  -- Disassembly at EIP
  local eip
  try
    eip = getEIP()
  catch
    eip = 0
  end
  if eip and eip > 0 then
    table.insert(lines, "=== DISASSEMBLY (at EIP: 0x" .. string.format("%X", eip) .. ") ===")
    table.insert(lines, ceai.getDisassembly(eip, 10))
    table.insert(lines, "")
  end

  table.insert(lines, "=== BREAKPOINTS ===")
  table.insert(lines, ceai.getBreakpoints())
  table.insert(lines, "")

  -- Address list (limited to 20)
  local addrs = ceai.getAddressList()
  if #addrs > 0 then
    local limit = math.min(#addrs, 20)
    table.insert(lines, string.format("=== MONITORED ADDRESSES (%d shown) ===", limit))
    for i = 1, limit do
      local addr = addrs[i]
      table.insert(lines, string.format("  [%s] %s: %s (%s)",
        addr.address, addr.name, addr.value, addr.type))
    end
    table.insert(lines, "")
  end

  table.insert(lines, "=== MODULES (first 10) ===")
  table.insert(lines, ceai.getModules())
  table.insert(lines, "")

  table.insert(lines, "=== STACK TRACE ===")
  table.insert(lines, ceai.getStackTrace())

  return table.concat(lines, "\n")
end

-- ============================================================
-- AI Communication
-- ============================================================

function ceai.sendToAI(message, callback)
  local context = ceai.gatherContext()

  local systemPrompt = [[You are an expert game debugging and reverse engineering assistant integrated into Cheat Engine.
You have access to the current debugging context shown below. Help the user:
- Analyze memory and find cheats
- Understand game mechanics and data structures
- Write assembly injections for Auto Assembler
- Write Lua automation scripts
- Analyze disassembly and suggest optimizations
- Explain code patterns
Be concise and practical. When suggesting Auto Assembler code, provide complete scripts.
When suggesting Lua code, wrap it in ```lua blocks for easy execution.]]

  local userContent = string.format("[%s]\n\n--- QUESTION ---\n%s", context, message)

  local requestBody = string.format(
    '{"model":"%s","temperature":0.2,"max_tokens":2048,"messages":[{"role":"system","content":"%s"},{"role":"user","content":"%s"}]}',
    ceai.escapeJson(ceai.model),
    ceai.escapeJson(systemPrompt),
    ceai.escapeJson(userContent)
  )

  -- Use CE's LuaInternet for HTTP
  local internet = createInternet()
  if not internet then
    if callback then callback(nil, "HTTP: createInternet() not available in this CE version") end
    return
  end

  local response = ""
  internet.onHTTPError = function(err)
    response = "[Error] " .. tostring(err)
  end

  local headers = "Content-Type: application/json\r\n"
  if ceai.api_key ~= "" then
    headers = headers .. "Authorization: Bearer " .. ceai.api_key .. "\r\n"
  end

  try
    response = internet.HTTPPost(ceai.endpoint, requestBody, headers, ceai.timeout)
  catch
    response = "[Error] HTTP request failed: " .. tostring(response)
  end

  internet.destroy()

  if callback then
    if response:find("^[Error]") then
      callback(nil, response)
    else
      -- Parse JSON response
      try
        local data = JSON.parse(response)
        if data and data.choices and data.choices[1] then
          callback(data.choices[1].message.content, nil)
        else
          callback(nil, "Invalid response format: " .. response:sub(1, 200))
        end
      catch
        callback(nil, "JSON parse error: " .. response:sub(1, 200))
      end
    end
  end
end

-- ============================================================
-- Code Execution (AI-suggested)
-- ============================================================

function ceai.executeCode(code)
  if not code or code == "" then return "No code to execute" end
  -- Extract Lua code from markdown code blocks
  local luaCode = code
  local match = string.match(code, "```lua\r?\n(.-)\r?\n```")
  if match then luaCode = match end
  -- Also try without lua tag
  if luaCode == code then
    match = string.match(code, "```[^\n]*\r?\n(.-)\r?\n```")
    if match then luaCode = match end
  end

  local status, result = pcall(function()
    local fn = load(luaCode, "=AI code", "t")
    if fn then return fn() end
    return "Code loaded but returned nil"
  end)

  if status then
    return tostring(result or "Code executed successfully")
  else
    return "Error: " .. tostring(result)
  end
end

-- ============================================================
-- Chat Window (Lua GUI)
-- ============================================================

function ceai.createChatWindow()
  if ceai.chatForm and not ceai.chatForm.destroyed then
    ceai.chatForm.bringToFront()
    return
  end

  -- Main form
  local form = createForm(false)
  form.Caption = "AI Chat - Cheat Engine"
  form.ClientWidth = 700
  form.ClientHeight = 500
  form.Position = 6  -- poScreenCenter
  form.BorderStyle = 3  -- bsSizeable

  -- Chat output (top)
  local chatMemo = createMemo(form)
  chatMemo.Parent = form
  chatMemo.Align = 0  -- alClient
  chatMemo.ReadOnly = true
  chatMemo.ScrollBars = 2  -- ssVertical
  chatMemo.Font.Name = "Consolas"
  chatMemo.Font.Size = 9

  -- Bottom panel for input
  local inputPanel = createPanel(form)
  inputPanel.Parent = form
  inputPanel.Align = 3  -- alBottom
  inputPanel.Height = 120
  inputPanel.BevelOuter = 0  -- bvNone

  -- Input memo
  local inputMemo = createMemo(inputPanel)
  inputMemo.Parent = inputPanel
  inputMemo.Align = 0  -- alClient
  inputMemo.ScrollBars = 2  -- ssVertical
  inputMemo.Font.Name = "Consolas"
  inputMemo.Font.Size = 9
  inputMemo.OnKeyDown = function(sender, key, shift)
    if key == 13 and shift and shift[ssCtrl] then  -- Ctrl+Enter
      ceai.doSend()
    end
  end

  -- Button panel
  local btnPanel = createPanel(inputPanel)
  btnPanel.Parent = inputPanel
  btnPanel.Align = 3  -- alBottom
  btnPanel.Height = 30
  btnPanel.BevelOuter = 0  -- bvNone

  -- Send button
  local btnSend = createButton(btnPanel)
  btnSend.Parent = btnPanel
  btnSend.Caption = "Send"
  btnSend.Width = 70
  btnSend.Left = 5
  btnSend.Top = 3
  btnSend.OnClick = function() ceai.doSend() end

  -- Context button
  local btnContext = createButton(btnPanel)
  btnContext.Parent = btnPanel
  btnContext.Caption = "Debug Context"
  btnContext.Width = 100
  btnContext.Left = 80
  btnContext.Top = 3
  btnContext.OnClick = function()
    local ctx = ceai.gatherContext()
    chatMemo.Lines.Add("[Context]:" .. ctx)
    chatMemo.Lines.Add("")
    chatMemo.Lines.Add("")
  end

  -- Execute button
  local btnExec = createButton(btnPanel)
  btnExec.Parent = btnPanel
  btnExec.Caption = "Execute Code"
  btnExec.Width = 100
  btnExec.Left = 185
  btnExec.Top = 3
  btnExec.OnClick = function()
    if ceai.lastAIResponse then
      local result = ceai.executeCode(ceai.lastAIResponse)
      chatMemo.Lines.Add("[Execute]: " .. result)
      chatMemo.Lines.Add("")
    else
      chatMemo.Lines.Add("[Execute]: No AI response to execute.")
      chatMemo.Lines.Add("")
    end
  end

  -- Clear button
  local btnClear = createButton(btnPanel)
  btnClear.Parent = btnPanel
  btnClear.Caption = "Clear"
  btnClear.Width = 70
  btnClear.Left = 290
  btnClear.Top = 3
  btnClear.OnClick = function()
    chatMemo.Lines.Clear()
    ceai.lastAIResponse = ""
    chatMemo.Lines.Add("Chat cleared.")
    chatMemo.Lines.Add("")
  end

  -- Settings button
  local btnSettings = createButton(btnPanel)
  btnSettings.Parent = btnPanel
  btnSettings.Caption = "Settings"
  btnSettings.Width = 70
  btnSettings.Left = 365
  btnSettings.Top = 3
  btnSettings.OnClick = function()
    ceai.showSettings()
  end

  -- Include context checkbox
  local chkContext = createCheckBox(btnPanel)
  chkContext.Parent = btnPanel
  chkContext.Caption = "Include debug context"
  chkContext.Checked = true
  chkContext.Left = 440
  chkContext.Top = 5
  chkContext.Width = 150

  -- Status label
  local statusLabel = createLabel(btnPanel)
  statusLabel.Parent = btnPanel
  statusLabel.Caption = "Ready"
  statusLabel.Left = 600
  statusLabel.Top = 6
  statusLabel.Width = 90
  statusLabel.Alignment = 2  -- taRightJustify

  -- Store references
  ceai.chatForm = form
  ceai.chatMemo = chatMemo
  ceai.inputMemo = inputMemo
  ceai.chkContext = chkContext
  ceai.statusLabel = statusLabel

  -- Welcome message
  chatMemo.Lines.Add("=== Cheat Engine AI Chat ===")
  chatMemo.Lines.Add("Endpoint: " .. ceai.endpoint)
  chatMemo.Lines.Add("Model: " .. ceai.model)
  chatMemo.Lines.Add("")
  chatMemo.Lines.Add("Press Ctrl+Enter to send messages.")
  chatMemo.Lines.Add("Use 'Debug Context' to dump current state.")
  chatMemo.Lines.Add("")

  form.show()
end

function ceai.doSend()
  if ceai.isSending then return end
  local message = ceai.inputMemo.Text
  if message == "" then return end

  ceai.isSending = true
  ceai.statusLabel.Caption = "Sending..."

  ceai.chatMemo.Lines.Add("[You]: " .. message)
  ceai.chatMemo.Lines.Add("")
  ceai.inputMemo.Text = ""

  ceai.sendToAI(message, function(response, error)
    ceai.isSending = false
    ceai.statusLabel.Caption = "Ready"

    if error then
      ceai.chatMemo.Lines.Add("[Error]: " .. error)
      ceai.chatMemo.Lines.Add("")
      return
    end

    if response then
      ceai.lastAIResponse = response
      ceai.chatMemo.Lines.Add("[AI]:" .. response)
      ceai.chatMemo.Lines.Add("")
      ceai.chatMemo.Lines.Add("")

      -- Scroll to bottom (add empty line to trigger scroll)
      ceai.chatMemo.Lines.Add("")
    end
  end)
end

function ceai.showSettings()
  local url = InputQuery("AI Settings", "API Endpoint:", ceai.endpoint)
  if url then ceai.endpoint = url end

  local model = InputQuery("AI Settings", "Model:", ceai.model)
  if model then ceai.model = model end

  local key = InputQuery("AI Settings", "API Key:", ceai.api_key)
  if key then ceai.api_key = key end

  showMessage("Settings updated.\nEndpoint: " .. ceai.endpoint .. "\nModel: " .. ceai.model)
end

-- ============================================================
-- Lua Console Commands
-- ============================================================

function ceai.init()
  -- Register commands accessible from Lua console
  ceai.commands = {
    context = function() return ceai.gatherContext() end,
    send = function(msg) ceai.sendToAI(msg, function(r,e) print(r or e or "") end) end,
    execute = function(code) return ceai.executeCode(code) end,
    chat = function() ceai.createChatWindow() end,
    disassembly = function(addr, count)
      return ceai.getDisassembly(addr or 0, count or 10)
    end,
    registers = function() return ceai.getRegisters() end,
    breakpoints = function() return ceai.getBreakpoints() end,
    modules = function() return ceai.getModules() end,
    stacktrace = function() return ceai.getStackTrace() end,
    settings = function() ceai.showSettings() end,
  }

  return true
end

-- ============================================================
-- Auto-initialize
-- ============================================================

ceai.init()

-- Try to add menu item to Tools menu
local function addMenuItem()
  local function doAdd()
    local mainForm = getMainForm()
    if not mainForm then return end
    local menu = mainForm.MainMenu1
    if not menu or not menu.Items then return end

    for i = 0, menu.Items.Count - 1 do
      local item = menu.Items.Item[i]
      if item and string.lower(item.Caption) == "tools" then
        -- Create new menu item
        local aiItem = createMenuItem()
        aiItem.Caption = "AI &Chat"
        aiItem.ShortCut = "Ctrl+Shift+A"
        aiItem.OnClick = function() ceai.createChatWindow() end
        -- Add to tools menu
        if item.Add then
          item.Add(aiItem)
        end
        return true
      end
    end
    return false
  end

  local ok, err = pcall(doAdd)
  if not ok then
    -- Menu manipulation failed, chat still accessible via Lua console: ceai.chat()
  end
end

addMenuItem()
