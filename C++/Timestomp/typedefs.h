#pragma once
#include <Windows.h>

#include "ntstructs.h"

char strNtSetInformationFile[] = { 'N','t','S','e','t','I','n','f','o','r','m','a','t','i','o','n','F','i','l','e', 0x0 };
char strNtQueryInformationFile[] = { 'N','t','Q','u','e','r','y','I','n','f','o','r','m','a','t','i','o','n','F','i','l','e', 0x0 };

typedef NTSTATUS(NTAPI *fnNtQueryInformationFile)(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_Out_ PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass
);

typedef NTSTATUS (NTAPI *fnNtSetInformationFile)(
	_In_  HANDLE                 FileHandle,
	_Out_ PIO_STATUS_BLOCK       IoStatusBlock,
	_In_  PVOID                  FileInformation,
	_In_  ULONG                  Length,
	_In_  FILE_INFORMATION_CLASS FileInformationClass
);