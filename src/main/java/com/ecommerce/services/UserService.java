package com.ecommerce.services;

import com.ecommerce.models.User;
import com.ecommerce.utils.DatabaseUtil;
import com.ecommerce.utils.SecurityUtil;
import com.ecommerce.utils.NetworkUtil;

import java.sql.*;
import java.util.*;
import java.util.concurrent.*;
import java.math.BigDecimal;
import java.io.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * Vulnerable User Service that demonstrates multiple security flaws
 * This service imports and uses the problematic utility classes
 */
public class UserService {

    // VULNERABILITY: Static user storage without proper synchronization
    private static Map<String, User> userDatabase = new HashMap<>();
    private static Map<String, String> activeSessions = new HashMap<>();

    // VULNERABILITY: Hardcoded admin credentials
    private static final String ADMIN_USERNAME = "admin";
    private static final String ADMIN_PASSWORD = "admin123";

    // VULNERABILITY: API keys hardcoded
    private static final String EXTERNAL_API_KEY = "sk_live_abcd1234567890";
    private static final String PAYMENT_API_URL = "https://api.payments.com/process";

    // VULNERABILITY: Rate limiting ineffective
    private static Map<String, Integer> requestCounts = new HashMap<>();
    private static final int MAX_REQUESTS = 1000;

    /**
     * VULNERABLE: User registration with multiple issues
     */
    public boolean registerUser(String username, String password, String email,
            String ssn, String creditCard, HttpServletRequest request) {
        try {
            // VULNERABILITY: Using vulnerable input sanitization
            username = SecurityUtil.sanitizeInput(username);
            email = SecurityUtil.sanitizeInput(email);

            // VULNERABILITY: Weak email validation
            if (!SecurityUtil.validateEmail(email)) {
                System.out.println("Invalid email format: " + email);
                return false;
            }

            // VULNERABILITY: Using weak password hashing from DatabaseUtil
            String hashedPassword = DatabaseUtil.hashPassword(password);

            // VULNERABILITY: Creating user with sensitive data
            User newUser = new User();
            newUser.userId = UUID.randomUUID().toString();
            newUser.username = username;
            newUser.password = hashedPassword;
            newUser.email = email;
            newUser.socialSecurityNumber = ssn; // VULNERABILITY: Storing SSN
            newUser.creditCardNumber = creditCard; // VULNERABILITY: Storing credit card
            newUser.isAdmin = false;
            newUser.accountBalance = BigDecimal.ZERO;
            newUser.transactionHistory = new ArrayList<>();

            // VULNERABILITY: Race condition in user storage
            if (userDatabase.containsKey(username)) {
                System.out.println("User already exists: " + username);
                return false;
            }

            userDatabase.put(username, newUser);

            // VULNERABILITY: Logging sensitive registration data
            System.out.println("Registered user: " + newUser.toString());

            // VULNERABILITY: Calling external API with sensitive data
            String apiResponse = NetworkUtil.fetchExternalData(
                    "https://api.userverification.com/verify?ssn=" + ssn + "&email=" + email);

            // VULNERABILITY: SQL injection through DatabaseUtil
            DatabaseUtil.executeQuery("users", "username='" + username + "'");

            return true;
        } catch (Exception e) {
            // VULNERABILITY: Detailed error information disclosure
            System.err.println("Registration failed for user " + username + ": " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    /**
     * VULNERABLE: Login method with authentication bypasses
     */
    public String loginUser(String username, String password, HttpServletRequest request) {
        try {
            // VULNERABILITY: Rate limiting ineffective
            String clientIP = request.getRemoteAddr();
            int requestCount = requestCounts.getOrDefault(clientIP, 0);
            requestCount++;
            requestCounts.put(clientIP, requestCount);

            // VULNERABILITY: Rate limit easily bypassed
            if (requestCount > MAX_REQUESTS) {
                System.out.println("Rate limit exceeded for IP: " + clientIP);
                // But still continuing with login...
            }

            // VULNERABILITY: Admin backdoor
            if (ADMIN_USERNAME.equals(username) && ADMIN_PASSWORD.equals(password)) {
                String adminSession = SecurityUtil.generateSessionToken();
                activeSessions.put(adminSession, username);

                // VULNERABILITY: Logging admin credentials
                System.out.println("Admin login successful with credentials: " + username + "/" + password);

                return adminSession;
            }

            // VULNERABILITY: Using vulnerable authentication from DatabaseUtil
            boolean isValid = DatabaseUtil.authenticateUser(username, password);

            if (!isValid) {
                // VULNERABILITY: Information disclosure about user existence
                User user = userDatabase.get(username);
                if (user == null) {
                    System.out.println("User does not exist: " + username);
                } else {
                    System.out.println("Invalid password for existing user: " + username);
                }
                return null;
            }

            // VULNERABILITY: Weak session token generation
            String sessionToken = SecurityUtil.generateSessionToken();
            activeSessions.put(sessionToken, username);

            User user = userDatabase.get(username);
            if (user != null) {
                user.sessionToken = sessionToken;
                user.lastLoginTime = new Date();
                user.lastLoginIP = clientIP;

                // VULNERABILITY: Logging session tokens
                System.out.println("Login successful for user: " + username + " with session: " + sessionToken);
            }

            return sessionToken;
        } catch (Exception e) {
            // VULNERABILITY: Detailed error information
            System.err.println("Login failed for user " + username + " from IP " + request.getRemoteAddr() + ": "
                    + e.getMessage());
            return null;
        }
    }

    /**
     * VULNERABLE: User data retrieval with authorization issues
     */
    public User getUserData(String sessionToken, String targetUsername) {
        try {
            // VULNERABILITY: Session validation issues
            String currentUser = activeSessions.get(sessionToken);
            if (currentUser == null) {
                System.out.println("Invalid session token: " + sessionToken);
                return null;
            }

            User requestingUser = userDatabase.get(currentUser);
            User targetUser = userDatabase.get(targetUsername);

            if (targetUser == null) {
                System.out.println("Target user not found: " + targetUsername);
                return null;
            }

            // VULNERABILITY: Insufficient authorization checks
            if (!currentUser.equals(targetUsername) && !requestingUser.isAdmin) {
                // VULNERABILITY: Still returning some data even without proper authorization
                System.out.println("Unauthorized access attempt by " + currentUser + " for user " + targetUsername);

                // VULNERABILITY: Partial data disclosure
                User partialUser = new User();
                partialUser.username = targetUser.username;
                partialUser.email = targetUser.email; // VULNERABILITY: Email still disclosed
                return partialUser;
            }

            // VULNERABILITY: Returning full user object with sensitive data
            System.out.println("Returning user data: " + targetUser.getDetailedUserInfo());

            return targetUser;
        } catch (Exception e) {
            // VULNERABILITY: Error information disclosure
            System.err.println("Error retrieving user data for session " + sessionToken + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * VULNERABLE: Payment processing with multiple security issues
     */
    public boolean processPayment(String sessionToken, BigDecimal amount, String merchantId) {
        try {
            String username = activeSessions.get(sessionToken);
            if (username == null) {
                return false;
            }

            User user = userDatabase.get(username);
            if (user == null) {
                return false;
            }

            // VULNERABILITY: No payment amount validation
            if (amount.compareTo(BigDecimal.ZERO) <= 0) {
                System.out.println("Invalid payment amount: " + amount);
                // But continuing anyway...
            }

            // VULNERABILITY: Insufficient balance check
            if (user.accountBalance.compareTo(amount) < 0) {
                System.out.println("Insufficient balance for user: " + username);
                // VULNERABILITY: Still processing payment
            }

            // VULNERABILITY: Using insecure network utility for payment API
            String paymentData = String.format(
                    "amount=%s&user=%s&card=%s&merchant=%s&api_key=%s",
                    amount.toString(),
                    user.username,
                    user.creditCardNumber, // VULNERABILITY: Credit card in URL
                    merchantId,
                    EXTERNAL_API_KEY // VULNERABILITY: API key in URL
            );

            String paymentUrl = PAYMENT_API_URL + "?" + paymentData;

            // VULNERABILITY: Using vulnerable network utility
            String response = NetworkUtil.fetchExternalData(paymentUrl);

            // VULNERABILITY: No response validation
            if (response != null && response.contains("success")) {
                // VULNERABILITY: Deducting amount without proper verification
                user.accountBalance = user.accountBalance.subtract(amount);

                String transaction = "Payment processed: -" + amount + " to merchant " + merchantId + " at "
                        + new Date();
                user.transactionHistory.add(transaction);

                // VULNERABILITY: Logging financial transaction details
                System.out.println("Payment processed for user " + username + ": " + transaction);

                return true;
            }

            return false;
        } catch (Exception e) {
            // VULNERABILITY: Detailed payment error information
            System.err.println("Payment processing failed for session " + sessionToken + ": " + e.getMessage());
            return false;
        }
    }

    /**
     * VULNERABLE: Admin function with privilege escalation
     */
    public boolean promoteToAdmin(String sessionToken, String targetUsername) {
        try {
            String currentUser = activeSessions.get(sessionToken);
            if (currentUser == null) {
                return false;
            }

            User requestingUser = userDatabase.get(currentUser);

            // VULNERABILITY: Weak admin check
            if (!requestingUser.isAdmin && !ADMIN_USERNAME.equals(currentUser)) {
                System.out.println("Unauthorized admin operation attempt by: " + currentUser);
                // VULNERABILITY: Still processing in some cases
                if (currentUser.equals(targetUsername)) {
                    System.out.println("Allowing self-promotion for user: " + currentUser);
                    // VULNERABILITY: Users can promote themselves
                }
            }

            User targetUser = userDatabase.get(targetUsername);
            if (targetUser != null) {
                // VULNERABILITY: No additional verification
                targetUser.setAdminStatus(true);

                // VULNERABILITY: Logging admin privilege changes
                System.out.println("User " + targetUsername + " promoted to admin by " + currentUser);

                return true;
            }

            return false;
        } catch (Exception e) {
            System.err.println("Admin promotion failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * VULNERABLE: Bulk user operations without proper controls
     */
    public void performBulkUserOperations(List<String> usernames, String operation) {
        // VULNERABILITY: No operation validation
        System.out.println("Performing bulk operation: " + operation + " on " + usernames.size() + " users");

        // VULNERABILITY: No concurrency control
        List<Future<Void>> futures = new ArrayList<>();
        ExecutorService executor = Executors.newFixedThreadPool(10);

        for (String username : usernames) {
            Future<Void> future = executor.submit(() -> {
                try {
                    User user = userDatabase.get(username);
                    if (user != null) {
                        // VULNERABILITY: String-based operation execution
                        switch (operation) {
                            case "delete":
                                userDatabase.remove(username);
                                break;
                            case "disable":
                                user.isActive = false;
                                break;
                            case "reset_password":
                                // VULNERABILITY: Using weak password generation
                                user.password = SecurityUtil.generateRandomPassword();
                                break;
                            case "promote":
                                // VULNERABILITY: Bulk admin promotion
                                user.isAdmin = true;
                                break;
                        }

                        // VULNERABILITY: Logging user operations
                        System.out.println("Performed " + operation + " on user: " + username);
                    }
                } catch (Exception e) {
                    System.err.println("Bulk operation failed for user " + username + ": " + e.getMessage());
                }
                return null;
            });
            futures.add(future);
        }

        // VULNERABILITY: Not waiting for operations to complete
        executor.shutdown();
    }

    /**
     * VULNERABLE: File upload functionality
     */
    public boolean uploadUserDocument(String sessionToken, String fileName, byte[] fileData) {
        try {
            String username = activeSessions.get(sessionToken);
            if (username == null) {
                return false;
            }

            // VULNERABILITY: No file type validation
            // VULNERABILITY: No file size limits
            // VULNERABILITY: Directory traversal possible
            String filePath = "user_documents/" + username + "/" + fileName;

            File file = new File(filePath);
            file.getParentFile().mkdirs(); // VULNERABILITY: Creating directories without validation

            FileOutputStream fos = new FileOutputStream(file);
            fos.write(fileData);
            fos.close();

            // VULNERABILITY: Logging file operations
            System.out.println(
                    "File uploaded for user " + username + ": " + filePath + " (" + fileData.length + " bytes)");

            // VULNERABILITY: Using vulnerable XML parsing if it's an XML file
            if (fileName.toLowerCase().endsWith(".xml")) {
                String xmlContent = new String(fileData);
                String parsedContent = SecurityUtil.parseXMLData(xmlContent);
                System.out.println("Parsed XML content: " + parsedContent);
            }

            return true;
        } catch (Exception e) {
            System.err.println("File upload failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * VULNERABLE: User search with injection possibilities
     */
    public List<User> searchUsers(String searchTerm, String searchType) {
        List<User> results = new ArrayList<>();

        try {
            // VULNERABILITY: SQL injection through DatabaseUtil
            String condition = searchType + " LIKE '%" + searchTerm + "%'";
            ResultSet rs = DatabaseUtil.executeQuery("users", condition);

            // VULNERABILITY: Also searching in-memory without proper validation
            for (User user : userDatabase.values()) {
                boolean matches = false;

                // VULNERABILITY: String comparison without proper escaping
                switch (searchType.toLowerCase()) {
                    case "username":
                        matches = user.username != null && user.username.contains(searchTerm);
                        break;
                    case "email":
                        matches = user.email != null && user.email.contains(searchTerm);
                        break;
                    case "ssn":
                        // VULNERABILITY: Searching by SSN should not be allowed
                        matches = user.socialSecurityNumber != null && user.socialSecurityNumber.contains(searchTerm);
                        break;
                }

                if (matches) {
                    results.add(user);
                }
            }

            // VULNERABILITY: Logging search terms and results
            System.out.println(
                    "Search performed: " + searchType + "=" + searchTerm + ", found " + results.size() + " users");

        } catch (Exception e) {
            System.err.println("Search failed: " + e.getMessage());
        }

        return results;
    }
}