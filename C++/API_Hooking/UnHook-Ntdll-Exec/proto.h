#pragma once
#include <Windows.h>
#include "structs.h"

// NTAPI Prototypes
typedef NTSTATUS(NTAPI* pfnNtWriteVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

typedef NTSTATUS(NTAPI* pfnNtAllocateVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

typedef NTSTATUS(NTAPI* pfnNtProtectVirtualMemory)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

typedef NTSTATUS(NTAPI* pfnRtlCreateUserThread)(
	IN HANDLE               ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN              CreateSuspended,
	IN ULONG                StackZeroBits,
	IN OUT PULONG           StackReserved,
	IN OUT PULONG           StackCommit,
	IN PVOID                StartAddress,
	IN PVOID                StartParameter OPTIONAL,
	OUT PHANDLE             ThreadHandle,
	OUT PCLIENT_ID          ClientID);


typedef NTSTATUS(NTAPI* pfnNtWaitForSingleObject)(
	IN HANDLE               ObjectHandle,
	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       TimeOut OPTIONAL);