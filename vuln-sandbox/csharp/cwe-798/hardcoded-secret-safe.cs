// CWE-798: Hardcoded Credentials — TRUE NEGATIVE
// Rule: csharp/hardcoded-secret
// API key loaded from environment variable — safe.

public class ApiClient
{
    // SAFE: API key loaded from environment variable at runtime
    private string apiKey = Environment.GetEnvironmentVariable("API_KEY") ?? string.Empty;

    public string GetApiKey() => apiKey;
}
