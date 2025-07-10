# DebugGuard
Windows kernel driver for protecting processes against memory manipulation, primarily, debugging.

## Features

- **Real-time Process Protection**: Monitors and protects specified processes from debugging attempts
- **Event-Driven Architecture**: No polling - responds instantly to system events
- **Multiple Detection Vectors**:
  - Usermode debugger detection (WinDbg, x64dbg, Cheat Engine, etc.)
  - Kernel debugger detection
  - Remote thread injection blocking
  - Suspicious module/DLL injection detection
  - Debug flag monitoring

## How It Works

The driver registers several kernel callbacks to monitor system activity:
- Process creation/termination notifications
- Image/module load notifications  
- Thread creation notifications

When a protected process is running, the driver will terminate it if:
- A known debugger/hacking tool is opened (like Cheat Engine)
- A debugger attempts to attach
- Suspicious DLLs are injected
- Remote threads are created

## Detection Methods

### Process Name Detection
Monitors for known debugger and hacking tool process names, including:
- x64dbg, WinDbg, OllyDbg
- IDA Pro
- Process Hacker

### Driver Detection
Checks for loaded kernel drivers associated with debugging tools:
- `dbk64.sys` / `dbk32.sys` (Cheat Engine)
- SoftICE drivers
- Process Monitor drivers

### Anti-Debug Checks
- ProcessDebugPort
- ProcessDebugFlags
- KdDebuggerEnabled/KdDebuggerNotPresent

```cpp
// Processes to protect
const char* targetProcesses[] = {
    "notepad.exe",
    "yourapp.exe"
};

// Configuration flags
const BOOLEAN TERMINATE_ON_DEBUGGER = TRUE;
const BOOLEAN TERMINATE_ON_INJECTION = TRUE;
```
