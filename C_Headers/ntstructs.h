#pragma once
#include "winuser.h"

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FNT%20Objects%2FSection%2FSECTION_INHERIT.html
typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, * PSECTION_INHERIT;

// https://www.nirsoft.net/kernel_struct/vista/UNICODE_STRING.html
typedef struct _UNICODE_STRING
{
	WORD Length;
	WORD MaximumLength;
	WORD* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

// https://www.nirsoft.net/kernel_struct/vista/OBJECT_ATTRIBUTES.html
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	PVOID RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

// https://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
typedef struct _CLIENT_ID
{
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FAPC%2FNtAlertThread.html
typedef struct _INITIAL_TEB {

	PVOID                StackBase;
	PVOID                StackLimit;
	PVOID                StackCommit;
	PVOID                StackCommitMax;
	PVOID                StackReserved;
} INITIAL_TEB, * PINITIAL_TEB;

// http://undocumented.ntinternals.net/index.html?page=UserMode%2FStructures%2FRTL_HEAP_DEFINITION.html
typedef struct _RTL_HEAP_DEFINITION {

	ULONG                   Length;
	ULONG                   Unknown1;
	ULONG                   Unknown2;
	ULONG                   Unknown3;
	ULONG                   Unknown4;
	ULONG                   Unknown5;
	ULONG                   Unknown6;
	ULONG                   Unknown7;
	ULONG                   Unknown8;
	ULONG                   Unknown9;
	ULONG                   Unknown10;
	ULONG                   Unknown11;
	ULONG                   Unknown12;
} RTL_HEAP_DEFINITION, * PRTL_HEAP_DEFINITION;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

/*
typedef enum _MEMORY_INFORMATION_CLASS {

	MemoryBasicInformation

} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;


typedef struct _MEMORY_BASIC_INFORMATION {

	PVOID                   BaseAddress;
	PVOID                   AllocationBase;
	ULONG                   AllocationProtect;
	ULONG                   RegionSize;
	ULONG                   State;
	ULONG                   Protect;
	ULONG                   Type;

} MEMORY_BASIC_INFORMATION, * PMEMORY_BASIC_INFORMATION;
*/