/*
A WINAPI* pointer is defined which will be assigned to MessageBoxW API.
When the DLL is injected into a running process, it will look for 
the MessageBoxW API call and hook into it.
A printf() function will run to say that the hook was attached.

Upon unhooking, the process will terminate and if more MessageBoxW API calls are in the
EXE, then none will be executed and program will be terminated
*/
#include <stdio.h>
#include <windows.h>

#include "detours/detours.h"

#pragma comment(lib, "user32.lib")

// pointer to original MessageBox
int (WINAPI* pOrigMessageBoxW)(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) = MessageBoxW;

// Hooking function
int HookedMessageBox(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType) 
{

	printf("HookedMessageBox() called. No popup on screen!\n");

	return IDOK;
}

// Set hooks on MessageBox
BOOL Hookem(void) 
{
	LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourAttach( &(PVOID&)pOrigMessageBoxW, 
				  HookedMessageBox);

	err = DetourTransactionCommit();

	printf("MessageBox() hooked! (res = %d)\n", err);

	return TRUE;
}

// Revert all changes to original code
BOOL UnHookem(void) 
{
	LONG err;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());
	DetourDetach( &(PVOID&)pOrigMessageBoxW, 
				  HookedMessageBox);

	err = DetourTransactionCommit();

	printf("Hook removed from MessageBox() with result = %d\n", err);

	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinst, 
					DWORD dwReason, 
					LPVOID reserved) 
{

	switch (dwReason) {
		case DLL_PROCESS_ATTACH:
			Hookem();
			break;

		case DLL_THREAD_ATTACH:
			break;

		case DLL_THREAD_DETACH:
			break;

		case DLL_PROCESS_DETACH:
			UnHookem();
			break;
	}

	return TRUE;
}

