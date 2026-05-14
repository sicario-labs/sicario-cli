// SAFE: java-ssrf-httpurlconnection-concat — URL validated against allowlist before connection
// Rule: java-ssrf-httpurlconnection-concat | CWE-918 | Expected: TrueNegative

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class SsrfServletSafe extends HttpServlet {

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(
        Arrays.asList("api.example.com", "data.example.com")
    );

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String targetUrl = request.getParameter("url");

        try {
            // SAFE: parse and validate the URL against an allowlist of trusted hosts
            URL url = new URL(targetUrl);
            if (!ALLOWED_HOSTS.contains(url.getHost())) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "URL not allowed");
                return;
            }

            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }

            response.getWriter().println(sb.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
