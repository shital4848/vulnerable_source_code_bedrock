package com.ecommerce.controllers;

import com.ecommerce.models.User;
import com.ecommerce.services.UserService;
import com.ecommerce.utils.DatabaseUtil;
import com.ecommerce.utils.SecurityUtil;
import com.ecommerce.utils.NetworkUtil;

import java.util.*;
import java.util.concurrent.*;
import java.math.BigDecimal;
import java.io.*;
import java.net.URL;

/**
 * VULNERABLE Main Application Controller
 * This class demonstrates multiple security vulnerabilities by using 
 * the problematic utility classes and services
 */
public class MainController {
    
    // VULNERABILITY: Static instance without proper initialization
    private static UserService userService = new UserService();
    
    // VULNERABILITY: Hardcoded sensitive configuration
    private static final String DB_BACKUP_URL = "ftp://backup.company.com";
    private static final String DB_BACKUP_USER = "backup_user";
    private static final String DB_BACKUP_PASS = "backup_pass_123";
    
    // VULNERABILITY: External API endpoints without validation
    private static final String[] EXTERNAL_APIS = {
        "https://api.creditcheck.com/verify",
        "https://api.background.com/check",
        "https://internal.company.com:8080/admin",  // SSRF target
        "file:///etc/passwd",  // Local file access
        "http://localhost:22/ssh"  // Port scanning
    };
    
    // VULNERABILITY: Shared state without synchronization
    private static Map<String, Object> applicationCache = new HashMap<>();
    private static List<String> auditLog = new ArrayList<>();
    
    /**
     * MAIN METHOD: Entry point with multiple vulnerabilities
     */
    public static void main(String[] args) {
        System.out.println("Starting Vulnerable E-commerce Application...");
        
        // VULNERABILITY: Command line argument injection
        if (args.length > 0) {
            String configFile = args[0];
            // VULNERABILITY: Loading arbitrary configuration files
            loadConfigurationFile(configFile);
        }
        
        // VULNERABILITY: Initializing with default admin user
        createDefaultAdminUser();
        
        // VULNERABILITY: Starting multiple vulnerable processes
        startBackgroundTasks();
        
        // VULNERABILITY: Processing test data without validation
        processTestUsers();
        
        // VULNERABILITY: Calling external APIs without proper validation
        performHealthChecks();
        
        System.out.println("Application startup complete!");
    }
    
    /**
     * VULNERABLE: Configuration file loading with multiple issues
     */
    private static void loadConfigurationFile(String fileName) {
        try {
            // VULNERABILITY: Directory traversal through DatabaseUtil
            String configContent = DatabaseUtil.readConfigFile(fileName);
            
            if (configContent != null) {
                // VULNERABILITY: Processing configuration without validation
                String[] lines = configContent.split("\n");
                
                for (String line : lines) {
                    if (line.contains("=")) {
                        String[] parts = line.split("=", 2);
                        String key = parts[0].trim();
                        String value = parts[1].trim();
                        
                        // VULNERABILITY: Setting system properties from untrusted input
                        System.setProperty(key, value);
                        applicationCache.put(key, value);
                        
                        // VULNERABILITY: Logging potentially sensitive configuration
                        auditLog.add("Configuration loaded: " + key + "=" + value);
                    }
                }
                
                // VULNERABILITY: Executing script commands from config
                if (configContent.contains("EXEC:")) {
                    String scriptCode = configContent.substring(configContent.indexOf("EXEC:") + 5);
                    // VULNERABILITY: Code injection through SecurityUtil
                    String result = SecurityUtil.executeUserScript(scriptCode);
                    System.out.println("Configuration script result: " + result);
                }
            }
        } catch (Exception e) {
            // VULNERABILITY: Detailed error information disclosure
            System.err.println("Configuration loading failed for file " + fileName + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * VULNERABLE: Creating default admin with weak credentials
     */
    private static void createDefaultAdminUser() {
        try {
            // VULNERABILITY: Hardcoded admin credentials
            boolean created = userService.registerUser(
                "admin",
                "admin123",  // VULNERABILITY: Weak password
                "admin@company.com",
                "123-45-6789",  // VULNERABILITY: Fake SSN
                "4111-1111-1111-1111",  // VULNERABILITY: Fake credit card
                null  // HttpServletRequest is null
            );
            
            if (created) {
                System.out.println("Default admin user created with credentials: admin/admin123");
            }
            
            // VULNERABILITY: Creating test users with predictable data
            for (int i = 1; i <= 10; i++) {
                userService.registerUser(
                    "testuser" + i,
                    "password" + i,  // VULNERABILITY: Predictable passwords
                    "test" + i + "@test.com",
                    "000-00-000" + i,  // VULNERABILITY: Predictable SSNs
                    "4000-0000-0000-000" + i,  // VULNERABILITY: Predictable cards
                    null
                );
            }
            
        } catch (Exception e) {
            System.err.println("Admin user creation failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Background tasks with security issues
     */
    private static void startBackgroundTasks() {
        // VULNERABILITY: Creating unlimited threads
        ExecutorService executor = Executors.newCachedThreadPool();
        
        // VULNERABILITY: Database backup task with credentials exposure
        executor.submit(() -> {
            while (true) {
                try {
                    // VULNERABILITY: Backing up to external FTP with hardcoded credentials
                    boolean success = NetworkUtil.uploadFile(
                        DB_BACKUP_URL,
                        DB_BACKUP_USER,
                        DB_BACKUP_PASS,
                        "database_backup.sql",
                        "backups/db_" + System.currentTimeMillis() + ".sql"
                    );
                    
                    if (success) {
                        auditLog.add("Database backup completed at " + new Date());
                    }
                    
                    // VULNERABILITY: Long sleep in background thread
                    Thread.sleep(3600000); // 1 hour
                } catch (Exception e) {
                    System.err.println("Backup task failed: " + e.getMessage());
                }
            }
        });
        
        // VULNERABILITY: External API monitoring task
        executor.submit(() -> {
            while (true) {
                try {
                    // VULNERABILITY: Making requests to potentially malicious URLs
                    for (String apiUrl : EXTERNAL_APIS) {
                        String response = NetworkUtil.fetchExternalData(apiUrl);
                        
                        // VULNERABILITY: Storing external responses without validation
                        applicationCache.put("api_response_" + apiUrl, response);
                        
                        // VULNERABILITY: Parsing XML responses without protection
                        if (response != null && response.trim().startsWith("<")) {
                            String parsed = SecurityUtil.parseXMLData(response);
                            applicationCache.put("parsed_" + apiUrl, parsed);
                        }
                    }
                    
                    Thread.sleep(300000); // 5 minutes
                } catch (Exception e) {
                    System.err.println("API monitoring task failed: " + e.getMessage());
                }
            }
        });
        
        // VULNERABILITY: Port scanning task
        executor.submit(() -> {
            while (true) {
                try {
                    // VULNERABILITY: Scanning internal network
                    String[] hosts = {"localhost", "127.0.0.1", "192.168.1.1", "10.0.0.1"};
                    int[] ports = {22, 23, 80, 443, 3306, 5432, 6379, 8080, 9200};
                    
                    for (String host : hosts) {
                        Map<Integer, Boolean> scanResults = NetworkUtil.scanPorts(host, ports);
                        applicationCache.put("scan_" + host, scanResults);
                        
                        // VULNERABILITY: Logging network scan results
                        System.out.println("Port scan completed for " + host + ": " + scanResults);
                    }
                    
                    Thread.sleep(1800000); // 30 minutes
                } catch (Exception e) {
                    System.err.println("Port scanning task failed: " + e.getMessage());
                }
            }
        });
    }
    
    /**
     * VULNERABLE: Processing test data with injection risks
     */
    private static void processTestUsers() {
        try {
            // VULNERABILITY: Processing untrusted test data
            String[] testUsernames = {
                "normaluser",
                "'; DROP TABLE users; --",  // SQL injection attempt
                "<script>alert('xss')</script>",  // XSS attempt
                "../../../admin",  // Path traversal attempt
                "admin' OR '1'='1",  // SQL injection attempt
                "eval('alert(1)')",  // Code injection attempt
            };
            
            for (String username : testUsernames) {
                try {
                    // VULNERABILITY: Processing malicious usernames
                    String sanitized = SecurityUtil.sanitizeInput(username);
                    
                    // VULNERABILITY: Using SQL injection prone method
                    DatabaseUtil.executeQuery("users", "username='" + sanitized + "'");
                    
                    // VULNERABILITY: Using vulnerable user search
                    List<User> searchResults = userService.searchUsers(username, "username");
                    
                    System.out.println("Processed test user: " + username + " (found " + searchResults.size() + " matches)");
                    
                } catch (Exception e) {
                    System.err.println("Error processing test user " + username + ": " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            System.err.println("Test user processing failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Health check system with SSRF vulnerabilities
     */
    private static void performHealthChecks() {
        try {
            // VULNERABILITY: Health checking internal systems
            String[] healthCheckUrls = {
                "http://internal-api:8080/health",
                "https://database.internal.com/status",
                "http://cache.internal.com:6379/info",
                "file:///proc/version",  // Local file access
                "http://169.254.169.254/latest/meta-data/",  // AWS metadata
                "http://metadata.google.internal/computeMetadata/v1/",  // GCP metadata
            };
            
            for (String url : healthCheckUrls) {
                try {
                    // VULNERABILITY: Making requests to internal URLs
                    String response = NetworkUtil.fetchExternalData(url);
                    
                    // VULNERABILITY: Storing internal system responses
                    applicationCache.put("health_" + url, response);
                    
                    System.out.println("Health check completed for: " + url);
                    
                } catch (Exception e) {
                    System.err.println("Health check failed for " + url + ": " + e.getMessage());
                }
            }
            
        } catch (Exception e) {
            System.err.println("Health check system failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Admin operations without proper authorization
     */
    public static void performAdminOperations(String operation, String[] parameters) {
        try {
            // VULNERABILITY: No authentication check for admin operations
            System.out.println("Performing admin operation: " + operation);
            
            switch (operation.toLowerCase()) {
                case "backup":
                    // VULNERABILITY: Database backup without authorization
                    performDatabaseBackup();
                    break;
                    
                case "restore":
                    // VULNERABILITY: Database restore from untrusted source
                    if (parameters.length > 0) {
                        restoreDatabaseFromFile(parameters[0]);
                    }
                    break;
                    
                case "cleanup":
                    // VULNERABILITY: Data cleanup without confirmation
                    performDataCleanup();
                    break;
                    
                case "promote":
                    // VULNERABILITY: Bulk user promotion
                    if (parameters.length > 0) {
                        List<String> usernames = Arrays.asList(parameters);
                        userService.performBulkUserOperations(usernames, "promote");
                    }
                    break;
                    
                case "exec":
                    // VULNERABILITY: Arbitrary code execution
                    if (parameters.length > 0) {
                        String code = String.join(" ", parameters);
                        String result = SecurityUtil.executeUserScript(code);
                        System.out.println("Code execution result: " + result);
                    }
                    break;
                    
                default:
                    // VULNERABILITY: Dynamic operation execution
                    System.out.println("Unknown operation: " + operation);
                    break;
            }
            
        } catch (Exception e) {
            System.err.println("Admin operation failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Database backup with credential exposure
     */
    private static void performDatabaseBackup() {
        try {
            // VULNERABILITY: Hardcoded database credentials
            String backupData = DatabaseUtil.executeQuery("users", "1=1").toString();
            
            // VULNERABILITY: Writing sensitive data to file
            FileWriter writer = new FileWriter("database_backup_" + System.currentTimeMillis() + ".sql");
            writer.write(backupData);
            writer.close();
            
            // VULNERABILITY: Uploading backup with credentials in logs
            boolean uploaded = NetworkUtil.uploadFile(
                "ftp://backup.example.com",
                "backup_user",
                "backup_password123",
                "database_backup.sql",
                "backup_" + System.currentTimeMillis() + ".sql"
            );
            
            System.out.println("Database backup completed, uploaded: " + uploaded);
            
        } catch (Exception e) {
            System.err.println("Database backup failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Database restore from untrusted file
     */
    private static void restoreDatabaseFromFile(String fileName) {
        try {
            // VULNERABILITY: Reading from arbitrary file path
            String restoreData = DatabaseUtil.readConfigFile(fileName);
            
            if (restoreData != null) {
                // VULNERABILITY: Executing SQL from untrusted source
                String[] sqlStatements = restoreData.split(";");
                
                for (String sql : sqlStatements) {
                    if (!sql.trim().isEmpty()) {
                        // VULNERABILITY: Executing arbitrary SQL
                        DatabaseUtil.executeQuery("users", sql.trim());
                    }
                }
                
                System.out.println("Database restored from file: " + fileName);
            }
            
        } catch (Exception e) {
            System.err.println("Database restore failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Data cleanup without proper validation
     */
    private static void performDataCleanup() {
        try {
            // VULNERABILITY: Clearing sensitive data without proper authorization
            applicationCache.clear();
            auditLog.clear();
            
            // VULNERABILITY: Bulk user operations without confirmation
            List<String> allUsers = new ArrayList<>();
            // Simulate getting all usernames
            for (int i = 1; i <= 100; i++) {
                allUsers.add("user" + i);
            }
            
            // VULNERABILITY: Mass user deletion
            userService.performBulkUserOperations(allUsers, "delete");
            
            System.out.println("Data cleanup completed - all user data deleted!");
            
        } catch (Exception e) {
            System.err.println("Data cleanup failed: " + e.getMessage());
        }
    }
    
    /**
     * VULNERABLE: Debug method exposing sensitive information
     */
    public static void printDebugInformation() {
        System.out.println("=== DEBUG INFORMATION ===");
        
        // VULNERABILITY: Exposing system properties
        System.out.println("System Properties:");
        Properties props = System.getProperties();
        for (Object key : props.keySet()) {
            System.out.println("  " + key + "=" + props.get(key));
        }
        
        // VULNERABILITY: Exposing application cache
        System.out.println("\nApplication Cache:");
        for (Map.Entry<String, Object> entry : applicationCache.entrySet()) {
            System.out.println("  " + entry.getKey() + "=" + entry.getValue());
        }
        
        // VULNERABILITY: Exposing audit log
        System.out.println("\nAudit Log:");
        for (String logEntry : auditLog) {
            System.out.println("  " + logEntry);
        }
        
        // VULNERABILITY: Memory information disclosure
        Runtime runtime = Runtime.getRuntime();
        System.out.println("\nMemory Information:");
        System.out.println("  Total Memory: " + runtime.totalMemory());
        System.out.println("  Free Memory: " + runtime.freeMemory());
        System.out.println("  Max Memory: " + runtime.maxMemory());
        
        System.out.println("=== END DEBUG INFORMATION ===");
    }
}