// VULNERABLE: java-ssrf-httpurlconnection-concat — new URL() with string concatenation
// Rule: java-ssrf-httpurlconnection-concat | CWE-918 | Severity: HIGH

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

public class SsrfServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userHost = request.getParameter("host");

        try {
            // VULNERABLE: user-controlled host used to construct outbound HTTP request
            // An attacker can pass: 169.254.169.254/latest/meta-data to access cloud metadata
            URL url = new URL("http://" + userHost + "/api");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream())
            );

            String line;
            StringBuilder result = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }

            response.getWriter().println(result.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
