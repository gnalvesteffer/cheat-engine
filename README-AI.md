# Cheat Engine AI Integration

## Quick Start (No Build Required)

The AI integration works as a **Lua autorun script** — it loads automatically in any Cheat Engine 7.x binary. No custom build needed.

### Installation

1. Copy `Cheat Engine/autorun/ai/ai_chat.lua` to your Cheat Engine's `autorun/ai/` folder
   (Create the `autorun/ai/` directory if it doesn't exist)
2. Start Cheat Engine
3. Go to **Tools -> AI Chat** (or press **Ctrl+Shift+A**)

### Configuration

Set these environment variables **before** launching Cheat Engine:

```bash
export AI_API_ENDPOINT="http://localhost:11434/v1/chat/completions"
export AI_MODEL="qwen3:32b"
export AI_API_KEY="your-key-here"  # For OpenAI-compatible APIs
```

Or use the **Settings** button in the chat window to configure endpoint, model, and API key.

### Usage

1. Open a target process in Cheat Engine
2. Open the AI Chat window
3. Ask questions like:
   - "What's at the current EIP?"
   - "Analyze this disassembly and explain what it does"
   - "Write an Auto Assembler script to nop the function at 0x..."
   - "Find all modules that are 32-bit"
   - "Write a Lua script to auto-scan for health values"
4. The AI has access to: process info, registers, disassembly, breakpoints, modules, monitored addresses, stack trace
5. Click **Execute Code** to run AI-suggested Lua code (sandboxed with pcall)
6. Click **Debug Context** to dump the full current state

---

## Custom Build (Optional)

If you want the AI chat integrated as a native form with a menu item in the main window:

### Prerequisites (Windows)

- **Lazarus 3.0+** with **FPC 3.2.2+**
- Clone this repo and open `Cheat Engine/cheatengine.lpi` in Lazarus

### Build Steps

```
1. Install Lazarus 3.0+ for Windows (https://www.lazarus-ide.org/)
2. Open "Cheat Engine/cheatengine.lpi" in Lazarus IDE
3. Build (F9)
```

### New Files

| File | Purpose |
|------|---------|
| `LuaAI.pas` | Exposes 16+ debugging functions to Lua API: `ai_readMemory()`, `ai_getRegisters()`, `ai_disassemble()`, `ai_getThreadInfo()`, `ai_getBreakpoints()`, `ai_getModuleList()`, `ai_getStackTrace()`, `ai_gatherContext()`, `ai_chat()`, etc. |
| `frmAIChatUnit.pas` | Chat form with debug context gathering, API communication, settings persistence |
| `frmAIChatUnit.lfm` | Form layout (chat memo, input, buttons) |
| `autorun/ai/ai_chat.lua` | Standalone Lua autorun script (no build needed) |

### Modified Files

| File | Change |
|------|--------|
| `LuaHandler.pas` | Added `LuaAI` unit to uses clause, calls `initializeLuaAI()` |
| `MainUnit.pas` | Added `miAIChat` menu item, `frmAIChat` form variable, `miAIChatClick` handler |
| `MainUnit.lfm` | Added "AI &Chat" menu item to Tools menu |
| `cheatengine.lpr` | Added `LuaAI` and `frmAIChatUnit` to project units |

---

## Lua API (Custom Build)

When built with the custom source, these additional Lua functions are available:

```lua
-- Memory
local hex = ai_readMemory(0x12345678, 32)  -- Read 32 bytes, returns hex string

-- Registers (table of name -> value)
local regs = ai_getRegisters()
print(regs["EAX"], regs["EIP"])

-- Current instruction pointer info
local curReg = ai_getCurrentRegister()  -- {name, value, disassembly}

-- Disassembly
local disasm = ai_disassemble(0x12345678, 10)  -- 10 instructions

-- Thread info
local threads = ai_getThreadInfo()  -- Table of {threadid, isSuspended, ...}

-- Breakpoints
local bps = ai_getBreakpoints()  -- Table of {address, active, size, method, trigger}

-- Modules
local mods = ai_getModuleList()  -- Table of {name, base, size}

-- Stack trace
local trace = ai_getStackTrace()  -- Array of frame strings

-- Process info
local info = ai_getProcessInfo()  -- {pid, name, architecture, bits}

-- Memory sections
local sections = ai_getMemorySections()  -- Table of memory regions

-- Comprehensive context
local context = ai_gatherContext()  -- Full debug context as string

-- AI Communication
ai_setKey("sk-...")  -- Set API key
local key = ai_getKey()  -- Get API key
local response = ai_chat("What is at EIP?")  -- Send to AI, get response

-- HTTP (for custom AI endpoints)
local result = ai_call("https://api.example.com/chat", jsonBody)
```

---

## Lua Autorun API (Works with Any CE Binary)

The standalone Lua script (`autorun/ai/ai_chat.lua`) exposes:

```lua
-- Open chat window
ceai.chat()

-- Get debug context
local ctx = ceai.context()
print(ctx)

-- Send message to AI
ceai.send("What's at the current EIP?")

-- Execute AI-suggested code
local result = ceai.execute("```lua\nprint('hello')\n```")

-- Individual context functions
local disasm = ceai.disassembly(getEIP(), 20)
local regs = ceai.registers()
local bps = ceai.breakpoints()
local mods = ceai.modules()
local trace = ceai.stacktrace()

-- Settings
ceai.settings()
```

---

## Architecture

```
┌─────────────────────────────────────────────┐
│              Cheat Engine                    │
├─────────────────────────────────────────────┤
│  Lua Interpreter                             │
│  ├── autorun/ai/ai_chat.lua (always loads)  │
│  │   ├── ceai.gatherContext()               │
│  │   ├── ceai.sendToAI()                    │
│  │   ├── ceai.executeCode()                 │
│  │   └── ceai.createChatWindow()            │
│  │                                           │
│  └── LuaAI.pas (custom build only)          │
│      ├── ai_readMemory()                    │
│      ├── ai_getRegisters()                  │
│      ├── ai_disassemble()                   │
│      ├── ai_getThreadInfo()                 │
│      ├── ai_getBreakpoints()                │
│      ├── ai_getModuleList()                 │
│      ├── ai_getStackTrace()                 │
│      ├── ai_gatherContext()                 │
│      ├── ai_chat() / ai_call()              │
│      └── ai_setKey() / ai_getKey()          │
├─────────────────────────────────────────────┤
│  frmAIChatUnit (custom build only)           │
│      ├── Chat UI with debug context          │
│      ├── Settings persistence (registry)     │
│      └── Direct API communication            │
└─────────────────────────────────────────────┘
         │
         ▼ (HTTP POST - OpenAI-compatible)
┌─────────────────────────────────────────────┐
│  AI Model (Ollama, OpenAI, etc.)             │
│  Receives: debug context + user question     │
│  Returns: analysis, suggestions, code        │
└─────────────────────────────────────────────┘
```

---

## Supported AI Endpoints

Any OpenAI-compatible API:

| Provider | Endpoint | Env Vars |
|----------|----------|----------|
| Ollama | `http://localhost:11434/v1/chat/completions` | `AI_MODEL=llama3.1` |
| OpenAI | `https://api.openai.com/v1/chat/completions` | `AI_API_KEY=sk-...`, `AI_MODEL=gpt-4o-mini` |
| Local vLLM | `http://localhost:8000/v1/chat/completions` | `AI_MODEL=your-model` |
| LM Studio | `http://localhost:1234/v1/chat/completions` | `AI_MODEL=your-model` |
