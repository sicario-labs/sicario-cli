// CWE-78: OS Command Injection - Safe Pattern
// Rule: csharp-command-injection-process-start
// Expected: TrueNegative

using System.Diagnostics;

public class FileProcessor
{
    public string ConvertFile(string fileName)
    {
        // SAFE: Static arguments, no user input in command string
        Process.Start("notepad.exe", "C:\\logs\\app.log");
        return "Processing";
    }

    public void RunScript()
    {
        // SAFE: Using ProcessStartInfo with separate arguments array
        var psi = new ProcessStartInfo
        {
            FileName = "convert",
            ArgumentList = { "input.jpg", "output.png" },
            UseShellExecute = false
        };
        Process.Start(psi);
    }
}
