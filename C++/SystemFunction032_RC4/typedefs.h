#pragma once
#include <Windows.h>

struct ustring {
	DWORD Length;
	DWORD MaximumLength;
	PUCHAR Buffer;
} _data, key;

typedef BOOL (WINAPI* SystemFunction040)
(
	_In_ _Out_	PVOID Memory,
	_In_		ULONG MemorySize,
	_In_		ULONG OptionFlags
);

typedef BOOL (WINAPI* SystemFunction041)
(
	_In_ _Out_	PVOID Memory,
	_In_		ULONG MemorySize,
	_In_		ULONG OptionFlags
);

typedef NTSTATUS(NTAPI* SystemFunction032)
(
	struct ustring* data,
	const struct ustring* key
);

typedef BOOL(WINAPI* SystemFunction036)
(
	void* buffer,
	ULONG len
);