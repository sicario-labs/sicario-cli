// SAFE: java-sqli-string-concat-variable — credentials loaded from environment variables
// Rule: java-sqli-string-concat-variable | CWE-798 | Expected: TrueNegative

import java.sql.Connection;
import java.sql.DriverManager;

public class HardcodedCredentialsSafe {

    public static Connection getConnection() throws Exception {
        // SAFE: credentials loaded from environment variables; never hardcoded in source
        String dbUrl = System.getenv("DATABASE_URL");
        String dbUser = System.getenv("DATABASE_USER");
        String dbPassword = System.getenv("DATABASE_PASSWORD");

        if (dbUrl == null || dbUser == null || dbPassword == null) {
            throw new IllegalStateException(
                "DATABASE_URL, DATABASE_USER, and DATABASE_PASSWORD environment variables must be set"
            );
        }

        return DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    public static void main(String[] args) throws Exception {
        try (Connection conn = getConnection()) {
            System.out.println("Connected to database: " + conn.getMetaData().getDatabaseProductName());
        }
    }
}
