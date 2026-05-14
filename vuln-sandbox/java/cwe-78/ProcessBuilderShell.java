// VULNERABLE: java-cmdi-processbuilder-shell — ProcessBuilder with shell invocation
// Rule: java-cmdi-processbuilder-shell | CWE-78 | Severity: CRITICAL

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class ProcessBuilderShell extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        String userCommand = request.getParameter("command");

        try {
            // VULNERABLE: shell invocation with user-controlled command string
            // An attacker can pass: ls && rm -rf / to execute arbitrary commands
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", userCommand);
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(proc.getInputStream())
            );

            String line;
            StringBuilder output = new StringBuilder();
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            response.getWriter().println(output.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
