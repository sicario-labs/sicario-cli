// SAFE: java-cmdi-runtime-exec-concat — allowlist validation prevents command injection
// Rule: java-cmdi-runtime-exec-concat | CWE-78 | Expected: TrueNegative

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class CommandInjectionSafe extends HttpServlet {

    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(
        Arrays.asList("localhost", "db.internal", "cache.internal")
    );

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String hostname = request.getParameter("host");

        // SAFE: hostname validated against an allowlist; passed as a separate argument, not shell string
        if (!ALLOWED_HOSTS.contains(hostname)) {
            try {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Host not allowed");
            } catch (Exception e) { e.printStackTrace(); }
            return;
        }

        try {
            // SAFE: command and argument passed as separate array elements; no shell interpretation
            ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", hostname);
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(proc.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            response.getWriter().println(output.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
