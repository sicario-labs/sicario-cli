// VULNERABLE: java-cmdi-runtime-exec-concat — Runtime.exec with string concatenation
// Rule: java-cmdi-runtime-exec-concat | CWE-78 | Severity: CRITICAL

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class CommandInjection extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String hostname = request.getParameter("host");

        try {
            // VULNERABLE: user-controlled input concatenated into shell command
            // An attacker can pass: localhost; cat /etc/passwd to read sensitive files
            Process proc = Runtime.getRuntime().exec("ping -c 1 " + hostname);

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
