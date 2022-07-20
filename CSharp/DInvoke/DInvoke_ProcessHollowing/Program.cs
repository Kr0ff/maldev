using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

using Invoke = DInvoke.DynamicInvoke;
using Data = DInvoke.Data;

namespace DInvoke_ProcessHollowing
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Structures.STARTUPINFO si = new Structures.STARTUPINFO();
            Structures.PROCESS_INFORMATION pi = new Structures.PROCESS_INFORMATION();
            Structures.PROCESS_BASIC_INFORMATION pbi = new Structures.PROCESS_BASIC_INFORMATION();
            //Data.Native.PROCESSINFOCLASS pic = new Data.Native.PROCESSINFOCLASS();

            

            const uint SUSPENDED_PROC = 0x4; 

            string Process = "C:\\Windows\\System32\\notepad.exe";

            // Create process
            bool _CreateProcess = Win32.CreateProcess(null, Process, IntPtr.Zero, IntPtr.Zero, false, SUSPENDED_PROC, IntPtr.Zero, null, ref si, out pi);
            if (_CreateProcess == false)
            {
                Console.WriteLine("[-] Failed creating process");
                return;
            }

            IntPtr hProcess = pi.hProcess;

            uint retLen = 0;

            if (ZwQueryInformationProcess(hProcess, 0, ref pbi, (uint)(IntPtr.Size * 6), ref retLen) == 0 )
            {
                Console.WriteLine("[+] Process information queried");
            } else { return; }

            
            IntPtr pImageBase = (IntPtr)((Int64)pbi.PebAddress + 0x10);
            IntPtr BufAddress = IntPtr.Zero;
            uint BytesToRead = 0;

            Invoke.Native.NtReadVirtualMemory(hProcess, pImageBase, BufAddress, ref BytesToRead);


            //DInvoke.DynamicInvoke.Native.NtQueryInformationProcess();
            //DInvoke.DynamicInvoke.Native.NtReadVirtualMemory();
            //DInvoke.DynamicInvoke.Native.NtWriteVirtualMemory();
        }

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtResumeThread(IntPtr hThread, uint dwSuspendCount);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref Structures.PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

    }


}
