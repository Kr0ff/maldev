.data
currentHash DWORD 0

.code
EXTERN SW2_GetSyscallNumber: PROC
    
WhisperMain PROC
    pop rax
    mov [rsp+ 8], rcx              ; Save registers.
    mov [rsp+16], rdx
    mov [rsp+24], r8
    mov [rsp+32], r9
    sub rsp, 28h
    mov ecx, currentHash
    call SW2_GetSyscallNumber
    add rsp, 28h
    mov rcx, [rsp+ 8]              ; Restore registers.
    mov rdx, [rsp+16]
    mov r8, [rsp+24]
    mov r9, [rsp+32]
    mov r10, rcx
    syscall                        ; Issue syscall
    ret
WhisperMain ENDP

NtCreateProcess PROC
    mov currentHash, 06A268ABBh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateProcess ENDP

NtCreateThreadEx PROC
    mov currentHash, 048D69681h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateThreadEx ENDP

NtOpenProcess PROC
    mov currentHash, 056187588h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcess ENDP

NtOpenProcessToken PROC
    mov currentHash, 00416089Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenProcessToken ENDP

NtTestAlert PROC
    mov currentHash, 05937409Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtTestAlert ENDP

NtOpenThread PROC
    mov currentHash, 03F0D2FB1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenThread ENDP

NtSuspendProcess PROC
    mov currentHash, 085DFA670h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendProcess ENDP

NtSuspendThread PROC
    mov currentHash, 0B41069A9h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSuspendThread ENDP

NtResumeProcess PROC
    mov currentHash, 0DB02F692h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeProcess ENDP

NtResumeThread PROC
    mov currentHash, 0765064F1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtResumeThread ENDP

NtGetContextThread PROC
    mov currentHash, 0B89336B1h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtGetContextThread ENDP

NtSetContextThread PROC
    mov currentHash, 0BC94F246h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtSetContextThread ENDP

NtClose PROC
    mov currentHash, 052CDA75Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtClose ENDP

NtReadVirtualMemory PROC
    mov currentHash, 005890F0Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtReadVirtualMemory ENDP

NtWriteVirtualMemory PROC
    mov currentHash, 0B935D7D3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWriteVirtualMemory ENDP

NtAllocateVirtualMemory PROC
    mov currentHash, 04DD53B1Bh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAllocateVirtualMemory ENDP

NtProtectVirtualMemory PROC
    mov currentHash, 03FA90907h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtProtectVirtualMemory ENDP

NtFreeVirtualMemory PROC
    mov currentHash, 001901B13h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtFreeVirtualMemory ENDP

NtQuerySystemInformation PROC
    mov currentHash, 01C07FD14h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQuerySystemInformation ENDP

NtQueryDirectoryFile PROC
    mov currentHash, 064C2061Ah    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryDirectoryFile ENDP

NtQueryInformationFile PROC
    mov currentHash, 0D4C04FF7h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationFile ENDP

NtQueryInformationProcess PROC
    mov currentHash, 0F236D5A3h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationProcess ENDP

NtQueryInformationThread PROC
    mov currentHash, 0B49C77BCh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueryInformationThread ENDP

NtCreateSection PROC
    mov currentHash, 0D34CD7DEh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtCreateSection ENDP

NtOpenSection PROC
    mov currentHash, 012CC761Fh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtOpenSection ENDP

NtMapViewOfSection PROC
    mov currentHash, 00AA429F5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtMapViewOfSection ENDP

NtUnmapViewOfSection PROC
    mov currentHash, 0154F3B94h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtUnmapViewOfSection ENDP

NtAdjustPrivilegesToken PROC
    mov currentHash, 007929493h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtAdjustPrivilegesToken ENDP

NtDeviceIoControlFile PROC
    mov currentHash, 05CFA3BF8h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtDeviceIoControlFile ENDP

NtQueueApcThread PROC
    mov currentHash, 008B00A1Dh    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtQueueApcThread ENDP

NtWaitForMultipleObjects PROC
    mov currentHash, 0C358C3D5h    ; Load function hash into global variable.
    call WhisperMain               ; Resolve function hash into syscall number and make the call
NtWaitForMultipleObjects ENDP

end