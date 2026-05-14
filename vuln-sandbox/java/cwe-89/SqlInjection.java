// VULNERABLE: java-sqli-statement-execute-concat — Statement.execute with string concatenation
// Rule: java-sqli-statement-execute-concat | CWE-89 | Severity: HIGH

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SqlInjection extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");
            Statement stmt = conn.createStatement();

            // VULNERABLE: user-controlled input concatenated directly into SQL query
            // An attacker can pass: 1 OR 1=1 -- to dump all users
            ResultSet rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + userId);

            while (rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }

            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
