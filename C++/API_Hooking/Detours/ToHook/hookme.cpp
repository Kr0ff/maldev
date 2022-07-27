/*
This exe is compiled and executed. 
Then the HookExe compiled DLL is injected into this process
and Detour hooks inside.
There is a defined method for MessageBoxW inside the DLL which will look for
the MessageBoxW API.
If its found, then a hook will be attached and upon unhooking the process will
be terminated.
*/

#include <windows.h>
#include <stdio.h>
#pragma comment(lib, "user32.lib")

int main() {
	printf("hookme.exe: Starting program....\n");

	MessageBoxW(NULL, L"MessageBox1", L"HOOK1", MB_OK);
	MessageBoxW(NULL, L"MessageBox2", L"HOOK2", MB_OK);
	MessageBoxW(NULL, L"MessageBox3", L"HOOK3", MB_OK);
	

	printf("hookme.exe: Exitting now...\n");

	return 0;
}