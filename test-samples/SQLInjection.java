package com.example.vulnerable;

import java.sql.*;

/**
 * VULNERABLE CODE - SQL Injection Examples
 * DO NOT USE IN PRODUCTION!
 */
public class SQLInjection {
    
    // CRITICAL: Direct SQL injection vulnerability
    public void unsafeLogin(String username, String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + 
                       "' AND password = '" + password + "'";
        // Attacker can inject: admin' OR '1'='1
    }
    
    // CRITICAL: SQL injection in search
    public void searchProducts(String searchTerm) {
        String sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
        // Vulnerable to: ' OR 1=1--
    }
    
    // HIGH: Dynamic table name injection
    public void dynamicQuery(String tableName, String userId) {
        String query = "SELECT * FROM " + tableName + " WHERE id = " + userId;
        // Can access any table
    }
    
    // CRITICAL: Order by injection
    public void sortUsers(String sortColumn) {
        String query = "SELECT * FROM users ORDER BY " + sortColumn;
        // Attacker can inject: (CASE WHEN (1=1) THEN 1 ELSE 2 END)
    }
    
    // HIGH: Stored procedure injection
    public void callStoredProc(String userInput) {
        String call = "CALL getUserInfo('" + userInput + "')";
        // Vulnerable to procedure injection
    }
}
