// VULNERABLE: java deserialization — ObjectInputStream with untrusted data
// Rule: java-deserialization-objectinputstream | CWE-502 | Severity: CRITICAL

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ObjectInputStream;

public class UnsafeDeserialization extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // VULNERABLE: deserializing untrusted data from HTTP request body
            // An attacker can craft a malicious serialized object to achieve RCE
            ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
            Object obj = ois.readObject();
            ois.close();

            response.getWriter().println("Deserialized: " + obj.getClass().getName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
