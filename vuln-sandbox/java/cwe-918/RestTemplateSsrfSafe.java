// SAFE: java-ssrf-resttemplate-concat — URL validated against allowlist before RestTemplate call
// Rule: java-ssrf-resttemplate-concat | CWE-918 | Expected: TrueNegative

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@RestController
public class RestTemplateSsrfSafe {

    private final RestTemplate restTemplate = new RestTemplate();

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(
        Arrays.asList("api.example.com", "data.example.com")
    );

    @GetMapping("/fetch")
    public String fetchData(@RequestParam String url) {
        // SAFE: parse and validate the URL against an allowlist of trusted hosts
        URI uri;
        try {
            uri = URI.create(url);
        } catch (IllegalArgumentException e) {
            return "Invalid URL";
        }

        if (!ALLOWED_HOSTS.contains(uri.getHost())) {
            return "URL not allowed";
        }

        return restTemplate.getForObject(uri, String.class);
    }
}
