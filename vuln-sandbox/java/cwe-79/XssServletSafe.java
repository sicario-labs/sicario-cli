// SAFE: java-xss-printwriter-html — user input HTML-encoded before rendering
// Rule: java-xss-printwriter-html | CWE-79 | Expected: TrueNegative

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.PrintWriter;

public class XssServletSafe extends HttpServlet {

    /**
     * Encode HTML special characters to prevent XSS.
     */
    private static String htmlEncode(String input) {
        if (input == null) return "";
        return input
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
            .replace("'", "&#x27;");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String name = request.getParameter("name");

        try {
            response.setContentType("text/html;charset=UTF-8");
            PrintWriter out = response.getWriter();

            // SAFE: user input HTML-encoded before being written to the response
            out.println("<html><body>");
            out.println("<h1>Hello, " + htmlEncode(name) + "!</h1>");
            out.println("</body></html>");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
