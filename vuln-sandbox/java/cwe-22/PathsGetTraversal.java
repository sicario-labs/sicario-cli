// VULNERABLE: java-path-paths-get-concat — Paths.get() with string concatenation
// Rule: java-path-paths-get-concat | CWE-22 | Severity: HIGH

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PathsGetTraversal extends HttpServlet {

    private static final String BASE_DIR = "/var/app/data";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String fileName = request.getParameter("path");

        try {
            // VULNERABLE: user-controlled path concatenated into Paths.get()
            // An attacker can pass: ../../etc/shadow to read sensitive system files
            byte[] content = Files.readAllBytes(
                Paths.get(BASE_DIR + "/" + fileName)
            );

            response.getOutputStream().write(content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
