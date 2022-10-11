using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Invoke = DInvoke.DynamicInvoke;
using Data = DInvoke.Data;
using Injection = DInvoke.Injection;

namespace DInvoke_MapViewOfSection
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string ntdll = "C:\\Windows";
            ntdll += "\\Sy";
            ntdll += "tem32\\n";
            ntdll += "tdll.dll";

            Console.WriteLine(ntdll);
            DInvoke.Data.PE.PE_MANUAL_MAP ntdllmap = DInvoke.ManualMap.Map.MapModuleToMemory("C:\\Windows\\System32\\ntdll.dll");
            if (ntdllmap.ModuleBase == IntPtr.Zero)
            {
                Console.WriteLine("No NTDLL for you my friend...");
                return;
            }
            Console.WriteLine("I've got you an NTDLL brother..");
            
            Console.ReadLine();

            
            Invoke.Generic.CallMappedDLLModuleExport(
                ntdllmap.PEINFO, 
                ntdllmap.ModuleBase, 
                "NtMapViewOfSection", 
                typeof dNtMapViewOfSection, 
                NtMapViewParams, 
                false);
            //Invoke.Generic.CallMappedDLLModule(ntdllmap.PEINFO, ntdllmap.ModuleBase);



        }
    }
}
