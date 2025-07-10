#include <ntddk.h>

// Pool flags for Windows 10 2004 and later
#ifndef POOL_FLAG_NON_PAGED
#define POOL_FLAG_NON_PAGED 0x0000000000000040UI64
#endif

// External functions
extern "C" {
    NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS* Process);
    NTKERNELAPI PUCHAR PsGetProcessImageFileName(PEPROCESS Process);
    NTKERNELAPI NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
        POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
    NTKERNELAPI NTSTATUS ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);
    NTKERNELAPI NTSTATUS ZwQueryInformationProcess(HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);
    NTKERNELAPI NTSTATUS PsSetLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
    NTKERNELAPI NTSTATUS PsRemoveLoadImageNotifyRoutine(PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
    NTKERNELAPI NTSTATUS PsSetCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
    NTKERNELAPI NTSTATUS PsRemoveCreateThreadNotifyRoutine(PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);
    NTKERNELAPI NTSTATUS ObOpenObjectByPointer(PVOID Object, ULONG HandleAttributes,
        PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode, PHANDLE Handle);
    NTKERNELAPI NTSTATUS ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes,
        PACCESS_STATE AccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType,
        KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);
    NTKERNELAPI NTSTATUS ZwQuerySystemInformation(ULONG SystemInformationClass,
        PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    extern POBJECT_TYPE* IoDriverObjectType;
}

// Access rights
#define PROCESS_TERMINATE           0x0001
#define PROCESS_VM_OPERATION        0x0008
#define PROCESS_VM_READ             0x0010
#define PROCESS_VM_WRITE            0x0020
#define PROCESS_QUERY_INFORMATION   0x0400

#define SystemProcessInformation    5

// System process information structures
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER SpareLi1;
    LARGE_INTEGER SpareLi2;
    LARGE_INTEGER SpareLi3;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR PageDirectoryBase;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// Configuration
const BOOLEAN TERMINATE_ON_DEBUGGER = TRUE;
const BOOLEAN TERMINATE_ON_INJECTION = TRUE;
const BOOLEAN TERMINATE_DEBUGGER_PROCESS = FALSE;

// Protected process structure
typedef struct _PROTECTED_PROCESS {
    HANDLE ProcessId;
    PEPROCESS Process;
    CHAR ProcessName[16];  // PsGetProcessImageFileName only returns 15 chars
    BOOLEAN BeingDebugged;
} PROTECTED_PROCESS;

// Processes to protect
const char* targetProcesses[] = {
    "notepad.exe",
    "calc.exe",
    "game.exe",
    "myapp.exe",
    "YourGame.exe",
    "RobloxPlayerBeta.exe",
    "MinecraftLauncher.exe",
    "javaw.exe"
};

// Debugger/hacker tool process names (includes truncated names due to 15 char limit)
const char* debuggerProcesses[] = {
    "cheatengine-x86_64.exe",
    "cheatengine-i386.exe",
    "Cheat Engine.exe",
    "cheatengine.exe",
    "cheatengine-x8",        // Truncated: cheatengine-x86_64.exe
    "cheatengine-i3",        // Truncated: cheatengine-i386.exe
    "Cheat Engine.e",        // Truncated: Cheat Engine.exe
    "ceserver.exe",
    "syncobj2",              // CE disguised process
    "syncobj2.exe",
    "syncobjs2",
    "syncobjs2.exe",
    "Tutorial-x86_6",        // Truncated: Tutorial-x86_64.exe
    "Tutorial-i386.",        // Truncated: Tutorial-i386.exe
    "x64dbg.exe",
    "x32dbg.exe",
    "ollydbg.exe",
    "windbg.exe",
    "idaq.exe",
    "idaq64.exe",
    "ida.exe",
    "ida64.exe",
    "processhacker.",        // Truncated: processhacker.exe
    "procmon.exe",
    "procmon64.exe",
    "HxD.exe",
    "HxD32.exe",
    "HxD64.exe",
    "httpanalyzerst",        // Truncated: httpanalyzerstdv7.exe
    "fiddler.exe",
    "wireshark.exe",
    "proxifier.exe",
    "KsDumperClient",        // Truncated: KsDumperClient.exe
    "KsDumper.exe",
    "scylla.exe",
    "scylla_x64.exe",
    "scylla_x86.exe",
    "protection_id.",        // Truncated: protection_id.exe
    "lordpe.exe",
    "ImportREC.exe",
    "immunitydebug",         // Truncated: immunitydebugger.exe
    "MegaDumper.exe"
};

// Suspicious module patterns
const WCHAR* suspiciousPatterns[] = {
    L"\\dbghelp.dll",
    L"\\dbgcore.dll",
    L"\\syser.sys",
    L"\\injector",
    L"\\hook",
    L"\\dbk64.sys",              // Cheat Engine driver
    L"\\dbk32.sys",              // Cheat Engine driver
    L"\\kernelmoduleunloader.sys",
    L"\\scylla",
    L"\\x64dbg",
    L"\\ollydbg",
    L"\\windbg",
    L"\\idaq",
    L"\\immunitydebugger"
};

// Known debugger drivers
const UNICODE_STRING debuggerDrivers[] = {
    RTL_CONSTANT_STRING(L"\\Driver\\dbk64"),
    RTL_CONSTANT_STRING(L"\\Driver\\dbk32"),
    RTL_CONSTANT_STRING(L"\\Driver\\PROCMON24"),
    RTL_CONSTANT_STRING(L"\\Driver\\SoftICE"),
    RTL_CONSTANT_STRING(L"\\Driver\\SICE"),
    RTL_CONSTANT_STRING(L"\\Driver\\SIWVID"),
    RTL_CONSTANT_STRING(L"\\Driver\\Syser")
};

// Globals
PROTECTED_PROCESS ProtectedList[20] = { 0 };
KSPIN_LOCK ProtectedListLock;

// Forward declarations
VOID TerminateProcess(HANDLE ProcessId, PCHAR Reason);
BOOLEAN IsDebuggerProcess(PUCHAR ProcessName);
VOID TerminateAllProtectedProcesses(PCHAR Reason);
BOOLEAN CheckDebuggerDrivers();

// ----==== Process Management ====----

BOOLEAN IsTargetProcess(PUCHAR ProcessName) {
    if (!ProcessName) return FALSE;

    for (int i = 0; i < sizeof(targetProcesses) / sizeof(targetProcesses[0]); i++) {
        if (_stricmp((const char*)ProcessName, targetProcesses[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN IsDebuggerProcess(PUCHAR ProcessName) {
    if (!ProcessName) return FALSE;

    for (int i = 0; i < sizeof(debuggerProcesses) / sizeof(debuggerProcesses[0]); i++) {
        if (_stricmp((const char*)ProcessName, debuggerProcesses[i]) == 0) {
            return TRUE;
        }
    }
    return FALSE;
}

VOID TerminateAllProtectedProcesses(PCHAR Reason) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&ProtectedListLock, &oldIrql);

    for (int i = 0; i < 20; i++) {
        if (ProtectedList[i].ProcessId != NULL) {
            HANDLE pid = ProtectedList[i].ProcessId;

            KeReleaseSpinLock(&ProtectedListLock, oldIrql);

            TerminateProcess(pid, Reason);

            KeAcquireSpinLock(&ProtectedListLock, &oldIrql);
        }
    }

    KeReleaseSpinLock(&ProtectedListLock, oldIrql);
}

VOID TerminateAllDebuggers() {
    ULONG bufferSize = 0;
    PVOID buffer = NULL;

    ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);

    if (bufferSize == 0) {
        return;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'dbgT');
    if (!buffer) {
        return;
    }

    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize))) {
        ExFreePool(buffer);
        return;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE) {
        if (processInfo->ImageName.Buffer && processInfo->ImageName.Length > 0) {
            ANSI_STRING processName;
            RtlUnicodeStringToAnsiString(&processName, &processInfo->ImageName, TRUE);

            if (IsDebuggerProcess((PUCHAR)processName.Buffer)) {
                TerminateProcess(processInfo->UniqueProcessId, "Debugger not allowed");
            }

            RtlFreeAnsiString(&processName);
        }

        if (processInfo->NextEntryOffset == 0) {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    ExFreePool(buffer);
}

BOOLEAN IsProtectedProcess(HANDLE ProcessId) {
    KIRQL oldIrql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&ProtectedListLock, &oldIrql);

    for (int i = 0; i < 20; i++) {
        if (ProtectedList[i].ProcessId == ProcessId) {
            found = TRUE;
            break;
        }
    }

    KeReleaseSpinLock(&ProtectedListLock, oldIrql);
    return found;
}

VOID AddProtectedProcess(HANDLE ProcessId, PEPROCESS Process, PUCHAR ProcessName) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&ProtectedListLock, &oldIrql);

    for (int i = 0; i < 20; i++) {
        if (ProtectedList[i].ProcessId == NULL) {
            ProtectedList[i].ProcessId = ProcessId;
            ProtectedList[i].Process = Process;
            ProtectedList[i].BeingDebugged = FALSE;
            RtlCopyMemory(ProtectedList[i].ProcessName, ProcessName, 15);
            ProtectedList[i].ProcessName[15] = '\0';
            ObReferenceObject(Process);
            break;
        }
    }

    KeReleaseSpinLock(&ProtectedListLock, oldIrql);
}

VOID RemoveProtectedProcess(HANDLE ProcessId) {
    KIRQL oldIrql;

    KeAcquireSpinLock(&ProtectedListLock, &oldIrql);

    for (int i = 0; i < 20; i++) {
        if (ProtectedList[i].ProcessId == ProcessId) {
            ObDereferenceObject(ProtectedList[i].Process);
            RtlZeroMemory(&ProtectedList[i], sizeof(PROTECTED_PROCESS));
            break;
        }
    }

    KeReleaseSpinLock(&ProtectedListLock, oldIrql);
}

PEPROCESS GetProtectedProcess(HANDLE ProcessId) {
    KIRQL oldIrql;
    PEPROCESS process = NULL;

    KeAcquireSpinLock(&ProtectedListLock, &oldIrql);

    for (int i = 0; i < 20; i++) {
        if (ProtectedList[i].ProcessId == ProcessId) {
            process = ProtectedList[i].Process;
            break;
        }
    }

    KeReleaseSpinLock(&ProtectedListLock, oldIrql);
    return process;
}

// ----==== Termination ====----

VOID TerminateProcess(HANDLE ProcessId, PCHAR Reason) {
    UNREFERENCED_PARAMETER(Reason);

    HANDLE hProcess;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;

    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_TERMINATE, &objAttr, &clientId))) {
        ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED);
        ZwClose(hProcess);
    }
}

// ----==== Detection Functions ====----

BOOLEAN IsSuspiciousModule(PUNICODE_STRING ModulePath) {
    if (!ModulePath || !ModulePath->Buffer) return FALSE;

    for (int i = 0; i < sizeof(suspiciousPatterns) / sizeof(suspiciousPatterns[0]); i++) {
        if (wcsstr(ModulePath->Buffer, suspiciousPatterns[i])) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN CheckExistingDebugger(HANDLE ProcessId) {
    HANDLE hProcess;
    CLIENT_ID clientId;
    OBJECT_ATTRIBUTES objAttr;
    BOOLEAN debuggerFound = FALSE;

    InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    clientId.UniqueProcess = ProcessId;
    clientId.UniqueThread = NULL;

    if (NT_SUCCESS(ZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &objAttr, &clientId))) {
        HANDLE debugPort = NULL;
        ULONG returnLength;

        // Check DebugPort
        if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, ProcessDebugPort,
            &debugPort, sizeof(HANDLE), &returnLength))) {
            if (debugPort != NULL) {
                debuggerFound = TRUE;
            }
        }

        // Check Debug Flags (0 when debugged)
        if (!debuggerFound) {
            ULONG debugFlags = 0;
            if (NT_SUCCESS(ZwQueryInformationProcess(hProcess, (PROCESSINFOCLASS)0x1F,
                &debugFlags, sizeof(ULONG), &returnLength))) {
                if (debugFlags == 0) {
                    debuggerFound = TRUE;
                }
            }
        }

        ZwClose(hProcess);
    }

    return debuggerFound;
}

BOOLEAN CheckKernelDebugger() {
    if (KdDebuggerNotPresent && !*KdDebuggerNotPresent) {
        return TRUE;
    }

    if (KdDebuggerEnabled && *KdDebuggerEnabled) {
        return TRUE;
    }

    return FALSE;
}

BOOLEAN CheckDebuggerDrivers() {
    for (int i = 0; i < sizeof(debuggerDrivers) / sizeof(UNICODE_STRING); i++) {
        PDRIVER_OBJECT driverObject;

        if (NT_SUCCESS(ObReferenceObjectByName(
            (PUNICODE_STRING)&debuggerDrivers[i],
            OBJ_CASE_INSENSITIVE,
            NULL,
            0,
            *IoDriverObjectType,
            KernelMode,
            NULL,
            (PVOID*)&driverObject
        ))) {
            ObDereferenceObject(driverObject);
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN CheckForRunningDebuggers() {
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    BOOLEAN debuggerFound = FALSE;

    ZwQuerySystemInformation(SystemProcessInformation, NULL, 0, &bufferSize);

    if (bufferSize == 0) {
        return FALSE;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'dbgC');
    if (!buffer) {
        return FALSE;
    }

    if (!NT_SUCCESS(ZwQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize))) {
        ExFreePool(buffer);
        return FALSE;
    }

    PSYSTEM_PROCESS_INFORMATION processInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

    while (TRUE) {
        if (processInfo->ImageName.Buffer && processInfo->ImageName.Length > 0) {
            ANSI_STRING processName;
            RtlUnicodeStringToAnsiString(&processName, &processInfo->ImageName, TRUE);

            if (IsDebuggerProcess((PUCHAR)processName.Buffer)) {
                debuggerFound = TRUE;
            }

            RtlFreeAnsiString(&processName);

            if (debuggerFound) {
                break;
            }
        }

        if (processInfo->NextEntryOffset == 0) {
            break;
        }

        processInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)processInfo + processInfo->NextEntryOffset);
    }

    ExFreePool(buffer);

    if (!debuggerFound && CheckDebuggerDrivers()) {
        debuggerFound = TRUE;
    }

    return debuggerFound;
}

// ----==== Event Callbacks ====----

VOID ImageLoadCallback(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo
) {
    UNREFERENCED_PARAMETER(ImageInfo);

    // Check for driver loads (ProcessId == 0)
    if (ProcessId == 0 && FullImageName && FullImageName->Buffer) {
        for (int i = 0; i < sizeof(debuggerDrivers) / sizeof(UNICODE_STRING); i++) {
            if (wcsstr(FullImageName->Buffer, debuggerDrivers[i].Buffer)) {
                if (TERMINATE_ON_DEBUGGER) {
                    TerminateAllProtectedProcesses("Debugger driver loaded");
                }
                return;
            }
        }
        return;
    }

    // Check for suspicious module loads in protected processes
    if (!IsProtectedProcess(ProcessId)) {
        return;
    }

    if (IsSuspiciousModule(FullImageName)) {
        if (TERMINATE_ON_INJECTION) {
            TerminateProcess(ProcessId, "Suspicious module injection");
        }
    }
}

VOID ThreadNotifyRoutine(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create
) {
    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create || !IsProtectedProcess(ProcessId)) {
        return;
    }

    HANDLE currentPid = PsGetProcessId(PsGetCurrentProcess());

    if (currentPid != ProcessId) {
        PEPROCESS currentProcess = PsGetCurrentProcess();
        PUCHAR creatorName = PsGetProcessImageFileName(currentProcess);

        // Allow system processes to create threads
        if (_stricmp((const char*)creatorName, "System") == 0 ||
            _stricmp((const char*)creatorName, "svchost.exe") == 0 ||
            _stricmp((const char*)creatorName, "csrss.exe") == 0 ||
            _stricmp((const char*)creatorName, "services.exe") == 0 ||
            _stricmp((const char*)creatorName, "lsass.exe") == 0) {
            return;
        }

        if (TERMINATE_ON_INJECTION) {
            TerminateProcess(ProcessId, "Remote thread injection");
        }
    }
}

VOID ProcessNotifyRoutine(HANDLE ParentId, HANDLE ProcessId, BOOLEAN Create) {
    UNREFERENCED_PARAMETER(ParentId);

    if (Create) {
        PEPROCESS Process;
        if (NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {
            PUCHAR processName = PsGetProcessImageFileName(Process);

            // Check if debugger/hacker tool was started
            if (IsDebuggerProcess(processName)) {
                if (TERMINATE_ON_DEBUGGER) {
                    TerminateAllProtectedProcesses("Debugger/hacker tool opened");

                    if (TERMINATE_DEBUGGER_PROCESS) {
                        TerminateProcess(ProcessId, "Debugger not allowed");
                    }
                }

                ObDereferenceObject(Process);
                return;
            }

            // Check if this is a process to protect
            if (IsTargetProcess(processName)) {
                if (CheckForRunningDebuggers()) {
                    if (TERMINATE_ON_DEBUGGER) {
                        ObDereferenceObject(Process);
                        TerminateProcess(ProcessId, "Debugger already running");
                        return;
                    }
                }

                AddProtectedProcess(ProcessId, Process, processName);

                if (CheckExistingDebugger(ProcessId)) {
                    if (TERMINATE_ON_DEBUGGER) {
                        TerminateProcess(ProcessId, "Started with debugger");
                    }
                }
            }

            ObDereferenceObject(Process);
        }
    }
    else {
        RemoveProtectedProcess(ProcessId);
    }
}

// ----==== Registration Functions ====----

NTSTATUS RegisterCallbacks() {
    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    PsSetLoadImageNotifyRoutine(ImageLoadCallback);
    PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);

    return STATUS_SUCCESS;
}

VOID UnregisterCallbacks() {
    PsSetCreateProcessNotifyRoutine(ProcessNotifyRoutine, TRUE);
    PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
    PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
}

// ----==== Driver Entry/Exit ====----

VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    UnregisterCallbacks();

    KIRQL oldIrql;
    KeAcquireSpinLock(&ProtectedListLock, &oldIrql);

    for (int i = 0; i < 20; i++) {
        if (ProtectedList[i].Process) {
            ObDereferenceObject(ProtectedList[i].Process);
        }
    }

    KeReleaseSpinLock(&ProtectedListLock, oldIrql);
}

extern "C" NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
) {
    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&ProtectedListLock);

    CheckForRunningDebuggers();

    NTSTATUS status = RegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    DriverObject->DriverUnload = DriverUnload;

    return STATUS_SUCCESS;
}