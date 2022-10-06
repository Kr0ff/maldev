#pragma once

#include "winuser.h"
#include "ntstructs.h"

typedef NTSTATUS(NTAPI* fNtCreateSection)(

	OUT PHANDLE             SectionHandle,
	IN ULONG                DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER       MaximumSize OPTIONAL,
	IN ULONG                PageAttributess,
	IN ULONG                SectionAttributes,
	IN HANDLE               FileHandle OPTIONAL);

typedef NTSTATUS(NTAPI* fNtMapViewOfSection)(

	IN HANDLE               SectionHandle,
	IN HANDLE               ProcessHandle,
	IN OUT PVOID*			BaseAddress OPTIONAL,
	IN ULONG                ZeroBits OPTIONAL,
	IN ULONG                CommitSize,
	IN OUT PLARGE_INTEGER   SectionOffset OPTIONAL,
	IN OUT PULONG           ViewSize,
	IN DWORD                InheritDisposition,
	IN ULONG                AllocationType OPTIONAL,
	IN ULONG                Protect);

typedef NTSTATUS(NTAPI* fNtUnmapViewOfSection)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress);

typedef NTSTATUS(NTAPI* fNtAllocateVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG                ZeroBits,
	IN OUT PULONG           RegionSize,
	IN ULONG                AllocationType,
	IN ULONG                Protect);

typedef NTSTATUS(NTAPI* fNtFreeVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID*				BaseAddress,
	IN OUT PULONG           RegionSize,
	IN ULONG                FreeType);

typedef NTSTATUS(NTAPI* fNtProtectVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN OUT PVOID*			BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection);

typedef NTSTATUS(NTAPI* fNtWriteVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN PVOID                Buffer,
	IN ULONG                NumberOfBytesToWrite,
	OUT PULONG              NumberOfBytesWritten OPTIONAL);

typedef PVOID(NTAPI* fRtlCreateHeap)(

	IN ULONG                Flags,
	IN PVOID                Base OPTIONAL,
	IN ULONG                Reserve OPTIONAL,
	IN ULONG                Commit,
	IN BOOLEAN              Lock OPTIONAL,
	IN PRTL_HEAP_DEFINITION RtlHeapParams OPTIONAL);

typedef PVOID(NTAPI* fRtlAllocateHeap)(

	IN PVOID                HeapHandle,
	IN ULONG                Flags,
	IN ULONG                Size);

typedef NTSTATUS(NTAPI* fRtlDestroyHeap)(

	IN PVOID               HeapHandle);

typedef BOOLEAN(NTAPI* fRtlFreeHeap)(

	IN PVOID                HeapHandle,
	IN ULONG                Flags OPTIONAL,
	IN PVOID                MemoryPointer);

typedef NTSTATUS(NTAPI* fNtDelayExecution)(

	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       DelayInterval);

typedef NTSTATUS(NTAPI* fNtAlertThread)(
	
	IN HANDLE               ThreadHandle);

typedef void(WINAPI* PIO_APC_ROUTINE)(PVOID, PIO_STATUS_BLOCK, DWORD);

typedef NTSTATUS(NTAPI* fNtQueueApcThread)(

	IN HANDLE               ThreadHandle,
	IN PIO_APC_ROUTINE      ApcRoutine,
	IN PVOID                ApcRoutineContext OPTIONAL,
	IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
	IN ULONG                ApcReserved OPTIONAL);

typedef NTSTATUS(NTAPI* fNtContinue)(

	IN PCONTEXT             ThreadContext,
	IN BOOLEAN              RaiseAlert);

typedef NTSTATUS(NTAPI* fNtCreateThread)(

	OUT PHANDLE             ThreadHandle,
	IN ACCESS_MASK          DesiredAccess,
	IN POBJECT_ATTRIBUTES   ObjectAttributes OPTIONAL,
	IN HANDLE               ProcessHandle,
	OUT PCLIENT_ID          ClientId,
	IN PCONTEXT             ThreadContext,
	IN PINITIAL_TEB         InitialTeb,
	IN BOOLEAN              CreateSuspended);

typedef NTSTATUS(NTAPI* fRtlCreateUserThread)(

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

typedef NTSTATUS(NTAPI* fNtDelayExecution)(

	IN BOOLEAN              Alertable,
	IN PLARGE_INTEGER       DelayInterval);

typedef NTSTATUS(NTAPI* fNtResumeThread)(

	IN HANDLE               ThreadHandle,
	OUT PULONG              SuspendCount OPTIONAL);

typedef NTSTATUS(NTAPI* fNtSuspendThread)(

	IN HANDLE               ThreadHandle,
	OUT PULONG              PreviousSuspendCount OPTIONAL);

/*
typedef NTSTATUS(NTAPI* fNtQueryVirtualMemory)(

	IN HANDLE               ProcessHandle,
	IN PVOID                BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID               Buffer,
	IN ULONG                Length,
	OUT PULONG              ResultLength OPTIONAL);
*/