// CWE-918: Server-Side Request Forgery — TRUE POSITIVE
// Rule: csharp/ssrf
// User-controlled host used in HttpClient.GetAsync URL.

using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class ProxyController : Controller
{
    private readonly HttpClient _httpClient;

    public ProxyController(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    [HttpGet("fetch")]
    public async Task<IActionResult> Fetch(string host)
    {
        // VULNERABLE: user-controlled host in URL
        var response = await _httpClient.GetAsync($"https://{host}/api/data");
        var content = await response.Content.ReadAsStringAsync();
        return Content(content);
    }
}
