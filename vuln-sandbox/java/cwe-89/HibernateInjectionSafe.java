// SAFE: java-sqli-hibernate-createquery-concat — named parameters prevent HQL injection
// Rule: java-sqli-hibernate-createquery-concat | CWE-89 | Expected: TrueNegative

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.query.Query;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;

public class HibernateInjectionSafe extends HttpServlet {

    private SessionFactory sessionFactory;

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");

        try (Session session = sessionFactory.openSession()) {
            // SAFE: named parameter :username used; user input never concatenated into HQL
            Query<Object[]> query = session.createQuery(
                "FROM User WHERE username = :username", Object[].class
            );
            query.setParameter("username", username);
            List<Object[]> results = query.list();

            for (Object[] row : results) {
                response.getWriter().println(row[0]);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
