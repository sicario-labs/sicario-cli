// CWE-89: SQL Injection - Safe Pattern
// Rule: csharp-sql-string-concat
// Expected: TrueNegative

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

        // SAFE: Using parameterized query with SqlParameter
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", userId);
        return cmd.ExecuteReader();
    }

    public void UpdateUser(string username, string email)
    {
        using var conn = new SqlConnection(_connectionString);
        conn.Open();

        // SAFE: Named parameters prevent SQL injection
        var cmd = new SqlCommand("UPDATE Users SET Email = @email WHERE Username = @username", conn);
        cmd.Parameters.AddWithValue("@email", email);
        cmd.Parameters.AddWithValue("@username", username);
        cmd.ExecuteNonQuery();
    }
}
