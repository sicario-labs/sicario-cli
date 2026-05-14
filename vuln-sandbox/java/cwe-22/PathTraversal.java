// VULNERABLE: java-path-file-concat — new File() with string concatenation
// Rule: java-path-file-concat | CWE-22 | Severity: HIGH

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;

public class PathTraversal extends HttpServlet {

    private static final String UPLOAD_DIR = "/var/app/uploads";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String filename = request.getParameter("file");

        try {
            // VULNERABLE: user-controlled filename concatenated into file path
            // An attacker can pass: ../../etc/passwd to read arbitrary files
            File file = new File(UPLOAD_DIR + "/" + filename);

            response.setContentType("application/octet-stream");
            OutputStream out = response.getOutputStream();

            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
