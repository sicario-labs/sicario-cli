// SAFE: java-cmdi-processbuilder-shell — ProcessBuilder used without shell; args as separate elements
// Rule: java-cmdi-processbuilder-shell | CWE-78 | Expected: TrueNegative

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class ProcessBuilderShellSafe extends HttpServlet {

    private static final Set<String> ALLOWED_SCRIPTS = new HashSet<>(
        Arrays.asList("report.sh", "cleanup.sh", "status.sh")
    );

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String scriptName = request.getParameter("script");

        // SAFE: script name validated against an allowlist
        if (!ALLOWED_SCRIPTS.contains(scriptName)) {
            try {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Script not allowed");
            } catch (Exception e) { e.printStackTrace(); }
            return;
        }

        try {
            // SAFE: command and argument passed as separate list elements; no shell=true
            ProcessBuilder pb = new ProcessBuilder("/opt/scripts/" + scriptName);
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
