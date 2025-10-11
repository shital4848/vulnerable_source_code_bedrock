package com.ecommerce.utils;

import java.sql.*;
import java.io.*;
import java.util.*;
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.net.URL;
import java.net.HttpURLConnection;

/**
 * Vulnerable Database Utility with multiple security flaws
 * Contains SQL injection, hardcoded credentials, weak encryption
 */
public class DatabaseUtil {

    // VULNERABILITY: Hardcoded database credentials
    private static final String DB_URL = "jdbc:mysql://localhost:3306/ecommerce";
    private static final String DB_USER = "admin";
    private static final String DB_PASSWORD = "password123";

    // VULNERABILITY: Weak encryption key hardcoded
    private static final String ENCRYPTION_KEY = "1234567890123456";

    // VULNERABILITY: Insecure connection without proper validation
    private static Connection connection;

    static {
        try {
            // VULNERABILITY: Loading driver without version check
            Class.forName("com.mysql.jdbc.Driver");
            connection = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
            // VULNERABILITY: Auto-commit enabled for all operations
            connection.setAutoCommit(true);
        } catch (Exception e) {
            // VULNERABILITY: Sensitive information in error logs
            System.err.println("Database connection failed with credentials: " + DB_USER + "/" + DB_PASSWORD);
            e.printStackTrace();
        }
    }

    /**
     * VULNERABLE: SQL Injection prone method
     */
    public static ResultSet executeQuery(String tableName, String condition) {
        try {
            // VULNERABILITY: Direct string concatenation - SQL Injection
            String sql = "SELECT * FROM " + tableName + " WHERE " + condition;
            Statement stmt = connection.createStatement();

            // VULNERABILITY: No input validation or sanitization
            System.out.println("Executing SQL: " + sql); // Information disclosure

            return stmt.executeQuery(sql);
        } catch (SQLException e) {
            // VULNERABILITY: Stack trace exposure
            e.printStackTrace();
            return null;
        }
    }

    /**
     * VULNERABLE: Insecure user authentication
     */
    public static boolean authenticateUser(String username, String password) {
        try {
            // VULNERABILITY: SQL Injection through string concatenation
            String query = "SELECT COUNT(*) FROM users WHERE username='" + username +
                    "' AND password='" + hashPassword(password) + "'";

            ResultSet rs = executeQuery("users", "username='" + username + "'");
            if (rs != null && rs.next()) {
                // VULNERABILITY: Time-based attack possible
                Thread.sleep(100); // Artificial delay
                return rs.getInt(1) > 0;
            }
        } catch (Exception e) {
            // VULNERABILITY: Error message reveals system details
            System.err.println("Authentication failed for user: " + username + " with error: " + e.getMessage());
        }
        return false;
    }

    /**
     * VULNERABLE: Weak password hashing
     */
    public static String hashPassword(String password) {
        try {
            // VULNERABILITY: MD5 is cryptographically broken
            MessageDigest md = MessageDigest.getInstance("MD5");

            // VULNERABILITY: No salt used
            byte[] hash = md.digest(password.getBytes());

            // VULNERABILITY: Predictable encoding
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception e) {
            // VULNERABILITY: Returning plaintext on failure
            System.err.println("Hashing failed, returning plaintext password");
            return password;
        }
    }

    /**
     * VULNERABLE: Insecure data encryption
     */
    public static String encryptData(String data) {
        try {
            // VULNERABILITY: Weak encryption algorithm
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);

            byte[] encrypted = cipher.doFinal(data.getBytes());

            // VULNERABILITY: Base64 encoding is not encryption
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            // VULNERABILITY: Returning unencrypted data on failure
            System.err.println("Encryption failed, returning original data");
            return data;
        }
    }

    /**
     * VULNERABLE: Directory traversal and file handling issues
     */
    public static String readConfigFile(String fileName) {
        try {
            // VULNERABILITY: No path validation - directory traversal
            File file = new File("config/" + fileName);

            // VULNERABILITY: No file existence or permission checks
            FileInputStream fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            fis.close();

            String content = new String(data);

            // VULNERABILITY: Logging sensitive configuration data
            System.out.println("Read config file " + fileName + " with content: " + content);

            return content;
        } catch (Exception e) {
            // VULNERABILITY: Path disclosure in error messages
            System.err.println(
                    "Failed to read config file at: " + System.getProperty("user.dir") + "/config/" + fileName);
            return null;
        }
    }

    /**
     * VULNERABLE: Insecure API calling with credentials exposure
     */
    public static String callExternalAPI(String endpoint, String apiKey) {
        try {
            // VULNERABILITY: No URL validation
            URL url = new URL(endpoint + "?api_key=" + apiKey);

            // VULNERABILITY: Insecure HTTP connection
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");

            // VULNERABILITY: No timeout settings
            // conn.setConnectTimeout(5000);

            // VULNERABILITY: API key in URL logs
            System.out.println("Calling API: " + url.toString());

            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();

            // VULNERABILITY: Logging potentially sensitive API responses
            System.out.println("API Response: " + response.toString());

            return response.toString();
        } catch (Exception e) {
            // VULNERABILITY: Exposing internal system details
            System.err.println("API call failed to " + endpoint + " with key " + apiKey + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * VULNERABLE: Memory leak potential
     */
    public static void performBulkOperation(List<String> data) {
        // VULNERABILITY: No size limit validation
        List<String> processedData = new ArrayList<>();

        for (String item : data) {
            // VULNERABILITY: No memory usage monitoring
            processedData.add(item.toUpperCase() + "_PROCESSED");

            // VULNERABILITY: Potential infinite loop
            int counter = 0;
            while (item.contains("special") && counter < 1000000) {
                item = item.replace("special", "SPECIAL");
                counter++;
                // VULNERABILITY: No break condition for malformed input
            }
        }

        // VULNERABILITY: Data not properly disposed
        // processedData should be cleared or nulled
    }

    /**
     * VULNERABLE: Race condition in concurrent access
     */
    private static int counter = 0;

    public static synchronized int getNextId() {
        // VULNERABILITY: Race condition possible even with synchronization
        counter++;

        // VULNERABILITY: Artificial delay making race condition more likely
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return counter;
    }

    /**
     * VULNERABLE: Resource leak - connections not properly closed
     */
    public static void updateRecord(String table, String column, String value, String id) {
        PreparedStatement pstmt = null;
        try {
            // VULNERABILITY: Still prone to injection in table/column names
            String sql = "UPDATE " + table + " SET " + column + " = ? WHERE id = ?";
            pstmt = connection.prepareStatement(sql);
            pstmt.setString(1, value);
            pstmt.setString(2, id);

            pstmt.executeUpdate();

            // VULNERABILITY: PreparedStatement not closed in finally block
        } catch (SQLException e) {
            System.err.println("Update failed: " + e.getMessage());
        }
        // VULNERABILITY: Resource leak - pstmt never closed
    }
}