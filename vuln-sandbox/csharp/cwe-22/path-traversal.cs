// CWE-22: Path Traversal — TRUE POSITIVE
// Rule: csharp/path-traversal
// User-controlled fileName used directly in File.ReadAllText without sanitization.

using System.IO;
using Microsoft.AspNetCore.Mvc;

public class FileController : Controller
{
    [HttpGet("download")]
    public IActionResult Download(string fileName)
    {
        // VULNERABLE: fileName is user-controlled and not sanitized
        var content = File.ReadAllText($"/uploads/{fileName}");
        return Content(content);
    }
}
