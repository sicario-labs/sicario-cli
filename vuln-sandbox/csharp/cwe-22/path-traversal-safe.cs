// CWE-22: Path Traversal — TRUE NEGATIVE
// Rule: csharp/path-traversal
// File path is a hardcoded constant — no user input involved.

using System.IO;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller
{
    [HttpGet("report")]
    public IActionResult GetReport()
    {
        // SAFE: hardcoded path, no user input
        var content = File.ReadAllText("/uploads/report.pdf");
        return Content(content);
    }
}
