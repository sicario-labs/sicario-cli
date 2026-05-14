// VULNERABLE: java-sqli-string-concat-variable — hardcoded database password in source
// Rule: java-sqli-string-concat-variable | CWE-798 | Severity: CRITICAL

import java.sql.Connection;
import java.sql.DriverManager;

public class HardcodedCredentials {

    // VULNERABLE: database password hardcoded in source code
    // Anyone with access to the repository can extract these credentials
    private static final String DB_URL = "jdbc:mysql://localhost/app";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "super_secret_password_123";

    public static Connection getConnection() throws Exception {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }

    // VULNERABLE: API key hardcoded as a string literal
    private static final String API_KEY = "sk-prod-abc123xyz789secretkey";

    public static String getApiKey() {
        return API_KEY;
    }

    public static void main(String[] args) throws Exception {
        Connection conn = getConnection();
        System.out.println("Connected: " + conn.isValid(5));
        conn.close();
    }
}
