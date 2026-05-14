using System;
using System.Data.SqlClient;

public class Test {
    public void Run() {
        var username = "admin";
        SqlCommand cmd = new SqlCommand();
        cmd.CommandText = "SELECT * FROM Users WHERE Name = '" + username + "'";
    }
}
