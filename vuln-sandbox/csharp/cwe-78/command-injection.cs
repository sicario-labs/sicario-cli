// CWE-78: OS Command Injection via Process.Start in C#
// Rule: csharp-command-injection-process-start
// Expected: TruePositive

using System.Diagnostics;

public class FileProcessor
{
    public string ConvertFile(string userInput)
    {
        // VULNERABLE: User input interpolated into process arguments
        Process.Start("cmd.exe", $"/c convert {userInput} output.png");
        return "Processing";
    }

    public void RunScript(string scriptName)
    {
        // VULNERABLE: User-controlled script name in process start
        Process.Start("powershell.exe", $"-File {scriptName}");
    }
}
