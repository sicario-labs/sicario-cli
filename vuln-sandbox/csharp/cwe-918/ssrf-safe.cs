// CWE-918: Server-Side Request Forgery — TRUE NEGATIVE
// Rule: csharp/ssrf
// Hardcoded URL — no user input in the request target.

using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class DataController : Controller
{
    private readonly HttpClient _httpClient;

    public DataController(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    [HttpGet("data")]
    public async Task<IActionResult> GetData()
    {
        // SAFE: hardcoded URL, no user input
        var response = await _httpClient.GetAsync("https://api.example.com/data");
        var content = await response.Content.ReadAsStringAsync();
        return Content(content);
    }
}
