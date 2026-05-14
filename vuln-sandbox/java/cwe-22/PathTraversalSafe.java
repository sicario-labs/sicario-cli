// SAFE: java-path-file-concat — canonical path check prevents directory traversal
// Rule: java-path-file-concat | CWE-22 | Expected: TrueNegative

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

public class PathTraversalSafe extends HttpServlet {

    private static final String UPLOAD_DIR = "/var/app/uploads";

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String filename = request.getParameter("file");

        try {
            // SAFE: resolve canonical path and verify it stays within the allowed directory
            File uploadDir = new File(UPLOAD_DIR).getCanonicalFile();
            File file = new File(uploadDir, filename).getCanonicalFile();

            if (!file.getPath().startsWith(uploadDir.getPath() + File.separator)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path");
                return;
            }

            if (!file.exists() || !file.isFile()) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
                return;
            }

            response.setContentType("application/octet-stream");
            OutputStream out = response.getOutputStream();

            try (FileInputStream fis = new FileInputStream(file)) {
                byte[] buffer = new byte[4096];
                int bytesRead;
                while ((bytesRead = fis.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
