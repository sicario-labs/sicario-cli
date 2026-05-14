// SAFE: java-path-paths-get-concat — path normalization and containment check prevent traversal
// Rule: java-path-paths-get-concat | CWE-22 | Expected: TrueNegative

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathsGetTraversalSafe extends HttpServlet {

    private static final Path UPLOAD_DIR = Paths.get("/var/app/uploads").normalize().toAbsolutePath();

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String filename = request.getParameter("file");

        try {
            // SAFE: normalize and verify the resolved path stays within the allowed directory
            Path filePath = UPLOAD_DIR.resolve(filename).normalize().toAbsolutePath();

            if (!filePath.startsWith(UPLOAD_DIR)) {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid file path");
                return;
            }

            if (!Files.exists(filePath) || !Files.isRegularFile(filePath)) {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "File not found");
                return;
            }

            byte[] content = Files.readAllBytes(filePath);
            response.setContentType("application/octet-stream");
            response.getOutputStream().write(content);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
