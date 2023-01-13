#pragma once
#include <Windows.h>
#include <iostream>

#define NTDLL L"ntdll.dll"

FARPROC _GetNtApiAddress(char *FunctionName) {

	HMODULE fHandle = NULL;
	FARPROC fAddress = NULL;

	fHandle = GetModuleHandle(NTDLL);
	if (fHandle == NULL) {
		return NULL;
	}

	fAddress = GetProcAddress(fHandle, FunctionName);
	if (fAddress == NULL) {
		return NULL;
	}

	return fAddress;
}