// SAFE: java-deserialization-objectinputstream — JSON deserialization used instead of ObjectInputStream
// Rule: java-deserialization-objectinputstream | CWE-502 | Expected: TrueNegative

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class UnsafeDeserializationSafe extends HttpServlet {

    private static final ObjectMapper mapper = new ObjectMapper();

    public static class UserData {
        public String username;
        public String email;
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) {
        try {
            // SAFE: Jackson JSON deserialization only parses data into a typed class;
            // it cannot execute arbitrary code unlike Java's ObjectInputStream
            UserData userData = mapper.readValue(request.getInputStream(), UserData.class);

            response.setContentType("application/json");
            response.getWriter().println(
                "{\"username\":\"" + userData.username + "\",\"email\":\"" + userData.email + "\"}"
            );
        } catch (IOException e) {
            try {
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid JSON");
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
    }
}
