// VULNERABLE: java-ssrf-resttemplate-concat — RestTemplate with concatenated URL
// Rule: java-ssrf-resttemplate-concat | CWE-918 | Severity: HIGH

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
public class RestTemplateSsrf {

    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/fetch")
    public String fetchData(@RequestParam String host) {
        // VULNERABLE: user-controlled host concatenated into RestTemplate URL
        // An attacker can pass: internal-service.local to probe internal services
        return restTemplate.getForObject("http://" + host + "/api/data", String.class);
    }
}
