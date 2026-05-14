// VULNERABLE: java-xss-printwriter-html — PrintWriter with HTML content and user input
// Rule: java-xss-printwriter-html | CWE-79 | Severity: HIGH

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

public class XssServlet extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");

        try {
            response.setContentType("text/html");
            PrintWriter writer = response.getWriter();

            // VULNERABLE: user input reflected directly into HTML response without encoding
            // An attacker can pass: <script>document.cookie</script> to steal session cookies
            writer.println("<html><body><h1>Welcome " + name + "</h1></body></html>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
