// CWE-89: SQL Injection via String Concatenation in C#
// Rule: csharp-sql-string-concat
// Expected: TruePositive

using System.Data.SqlClient;

public class UserRepository
{
    private readonly string _connectionString;

    public UserRepository(string connectionString)
    {
        _connectionString = connectionString;
    }

    public object GetUser(string userId)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();

        // VULNERABLE: User input concatenated into SQL command
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + userId, conn);
        return cmd.ExecuteReader();
    }

    public void UpdateUser(string username, string email)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();

        // VULNERABLE: CommandText built with string concatenation
        var cmd = new SqlCommand("", conn);
        cmd.CommandText = "UPDATE Users SET Email = '" + email + "' WHERE Username = '" + username + "'";
        cmd.ExecuteNonQuery();
    }
}
