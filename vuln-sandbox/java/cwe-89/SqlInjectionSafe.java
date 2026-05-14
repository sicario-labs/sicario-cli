// SAFE: java-sqli-statement-execute-concat — PreparedStatement prevents SQL injection
// Rule: java-sqli-statement-execute-concat | CWE-89 | Expected: TrueNegative

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class SqlInjectionSafe extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String userId = request.getParameter("id");

        try {
            Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/app", "root", "");

            // SAFE: PreparedStatement uses a parameterized placeholder; user input never concatenated
            PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
            stmt.setString(1, userId);
            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {
                response.getWriter().println(rs.getString("username"));
            }

            conn.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
