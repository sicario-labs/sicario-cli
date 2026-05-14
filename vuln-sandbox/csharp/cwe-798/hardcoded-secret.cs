// CWE-798: Hardcoded Credentials — TRUE POSITIVE
// Rule: csharp/hardcoded-secret
// API key assigned as a string literal in source code.

public class ApiClient
{
    // VULNERABLE: hardcoded API key exposed in source code
    private string apiKey = "sk-prod-abc123xyz456def789";

    public string GetApiKey() => apiKey;
}
