// VULNERABLE: java-sqli-hibernate-createquery-concat — Hibernate createQuery with string concatenation
// Rule: java-sqli-hibernate-createquery-concat | CWE-89 | Severity: HIGH

import org.hibernate.Session;
import org.hibernate.SessionFactory;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class HibernateInjection extends HttpServlet {

    private SessionFactory sessionFactory;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");

        Session session = sessionFactory.openSession();

        // VULNERABLE: user input concatenated into HQL query string
        // An attacker can pass: ' OR '1'='1 to bypass authentication
        List<?> users = session.createQuery(
            "FROM User WHERE username = '" + username + "'"
        ).list();

        try {
            for (Object user : users) {
                response.getWriter().println(user.toString());
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            session.close();
        }
    }
}
