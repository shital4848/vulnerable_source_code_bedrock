package com.ecommerce.utils;

import java.io.*;
import java.util.*;
import java.util.regex.*;
import javax.xml.parsers.*;
import org.w3c.dom.*;
import java.nio.file.*;
import java.security.SecureRandom;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;

/**
 * Vulnerable Security Utility with multiple flaws
 * Contains XXE, XSS, CSRF, weak randomization issues
 */
public class SecurityUtil {

    // VULNERABILITY: Weak random number generator
    private static Random random = new Random(System.currentTimeMillis());

    // VULNERABILITY: Predictable session tokens
    private static final String[] SESSION_PREFIXES = { "sess_", "token_", "auth_" };

    // VULNERABILITY: Hardcoded security keys
    private static final String CSRF_SECRET = "csrf_secret_key_123";
    private static final String SESSION_SECRET = "session_secret_456";

    /**
     * VULNERABLE: XSS-prone input sanitization
     */
    public static String sanitizeInput(String input) {
        if (input == null) {
            return "";
        }

        // VULNERABILITY: Incomplete XSS protection
        String sanitized = input.replaceAll("<script>", "")
                .replaceAll("</script>", "")
                .replaceAll("javascript:", "");

        // VULNERABILITY: Bypasses are possible with different cases
        // Missing: <Script>, JAVASCRIPT:, eval(), etc.

        // VULNERABILITY: SQL injection characters not filtered
        // Still allows: ', ", ;, --, /*

        System.out.println("Original input: " + input);
        System.out.println("Sanitized input: " + sanitized);

        return sanitized;
    }

    /**
     * VULNERABLE: XML External Entity (XXE) attack vector
     */
    public static String parseXMLData(String xmlContent) {
        try {
            // VULNERABILITY: XML parser allows external entities
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

            // VULNERABILITY: XXE protection not enabled
            // factory.setFeature("http://xml.org/sax/features/external-general-entities",
            // false);
            // factory.setFeature("http://xml.org/sax/features/external-parameter-entities",
            // false);

            DocumentBuilder builder = factory.newDocumentBuilder();

            // VULNERABILITY: Processing untrusted XML input
            Document doc = builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));

            Element root = doc.getDocumentElement();
            String result = root.getTextContent();

            // VULNERABILITY: Logging potentially malicious XML content
            System.out.println("Parsed XML content: " + xmlContent);

            return result;
        } catch (Exception e) {
            // VULNERABILITY: Detailed error information disclosure
            System.err.println("XML parsing failed with detailed error: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * VULNERABLE: Weak session token generation
     */
    public static String generateSessionToken() {
        // VULNERABILITY: Predictable token generation
        String prefix = SESSION_PREFIXES[random.nextInt(SESSION_PREFIXES.length)];

        // VULNERABILITY: Weak randomness source
        long timestamp = System.currentTimeMillis();
        int randomPart = random.nextInt(10000);

        // VULNERABILITY: Predictable pattern
        String token = prefix + timestamp + "_" + randomPart;

        // VULNERABILITY: Token structure disclosure
        System.out.println("Generated session token: " + token);

        return token;
    }

    /**
     * VULNERABLE: Insecure CSRF token validation
     */
    public static boolean validateCSRFToken(String token, String userSession) {
        // VULNERABILITY: Weak CSRF token validation logic
        if (token == null || userSession == null) {
            return false;
        }

        // VULNERABILITY: Predictable CSRF token generation
        String expectedToken = userSession + "_" + CSRF_SECRET;

        // VULNERABILITY: String comparison without constant time
        boolean isValid = token.equals(expectedToken);

        // VULNERABILITY: Timing attack possible
        try {
            Thread.sleep(isValid ? 10 : 50);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // VULNERABILITY: Logging security-sensitive information
        System.out.println("CSRF validation - Expected: " + expectedToken + ", Received: " + token);

        return isValid;
    }

    /**
     * VULNERABLE: Path traversal in file operations
     */
    public static String readUserFile(String userId, String fileName) {
        try {
            // VULNERABILITY: No path validation - directory traversal
            String filePath = "users/" + userId + "/" + fileName;

            // VULNERABILITY: No file access control checks
            File file = new File(filePath);

            // VULNERABILITY: Absolute path construction allows traversal
            String absolutePath = file.getAbsolutePath();

            // VULNERABILITY: Reading arbitrary files
            byte[] content = Files.readAllBytes(Paths.get(absolutePath));
            String fileContent = new String(content);

            // VULNERABILITY: Logging file contents
            System.out.println("Read file " + absolutePath + " with content: " + fileContent);

            return fileContent;
        } catch (Exception e) {
            // VULNERABILITY: Path disclosure in error messages
            System.err.println("Failed to read file: " + e.getMessage());
            return null;
        }
    }

    /**
     * VULNERABLE: Code injection through script execution
     */
    public static String executeUserScript(String scriptCode) {
        try {
            // VULNERABILITY: Arbitrary code execution
            ScriptEngineManager manager = new ScriptEngineManager();
            ScriptEngine engine = manager.getEngineByName("JavaScript");

            // VULNERABILITY: No sandboxing or input validation
            Object result = engine.eval(scriptCode);

            String output = result != null ? result.toString() : "null";

            // VULNERABILITY: Logging executed code
            System.out.println("Executed script: " + scriptCode + " with result: " + output);

            return output;
        } catch (Exception e) {
            // VULNERABILITY: Error details could reveal system information
            System.err.println("Script execution failed: " + e.getMessage());
            return "Error: " + e.getMessage();
        }
    }

    /**
     * VULNERABLE: Weak input validation using regex
     */
    public static boolean validateEmail(String email) {
        // VULNERABILITY: Weak email validation regex
        String emailRegex = ".*@.*\\..*";

        // VULNERABILITY: ReDoS (Regular Expression Denial of Service) possible
        Pattern pattern = Pattern.compile(emailRegex);
        Matcher matcher = pattern.matcher(email);

        boolean isValid = matcher.matches();

        // VULNERABILITY: Information disclosure
        System.out.println("Email validation for " + email + ": " + isValid);

        return isValid;
    }

    /**
     * VULNERABLE: Insecure random password generation
     */
    public static String generateRandomPassword() {
        // VULNERABILITY: Weak character set
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";

        StringBuilder password = new StringBuilder();

        // VULNERABILITY: Weak random number generator
        for (int i = 0; i < 8; i++) {
            int index = random.nextInt(chars.length());
            password.append(chars.charAt(index));
        }

        String generatedPassword = password.toString();

        // VULNERABILITY: Logging generated passwords
        System.out.println("Generated password: " + generatedPassword);

        return generatedPassword;
    }

    /**
     * VULNERABLE: Information disclosure through debug mode
     */
    private static boolean DEBUG_MODE = true;

    public static void debugLog(String message, Object... args) {
        if (DEBUG_MODE) {
            // VULNERABILITY: Debug mode always enabled in production
            System.out.println("DEBUG: " + String.format(message, args));

            // VULNERABILITY: Stack trace in debug output
            for (StackTraceElement element : Thread.currentThread().getStackTrace()) {
                System.out.println("  at " + element.toString());
            }
        }
    }

    /**
     * VULNERABLE: Insecure deserialization
     */
    public static Object deserializeUserData(byte[] data) {
        try {
            // VULNERABILITY: Deserializing untrusted data
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);

            // VULNERABILITY: No class validation during deserialization
            Object obj = ois.readObject();

            ois.close();
            bis.close();

            // VULNERABILITY: Logging deserialized object details
            System.out.println("Deserialized object: " + obj.getClass().getName());

            return obj;
        } catch (Exception e) {
            // VULNERABILITY: Detailed exception information
            System.err.println("Deserialization failed: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * VULNERABLE: Race condition in security check
     */
    private static Map<String, Integer> loginAttempts = new HashMap<>();

    public static boolean checkLoginAttempts(String username) {
        // VULNERABILITY: Race condition in concurrent access
        Integer attempts = loginAttempts.get(username);

        if (attempts == null) {
            attempts = 0;
        }

        // VULNERABILITY: No synchronization
        attempts++;
        loginAttempts.put(username, attempts);

        // VULNERABILITY: Hardcoded limit, easy to bypass
        boolean allowed = attempts <= 3;

        // VULNERABILITY: Information disclosure
        System.out.println("Login attempts for " + username + ": " + attempts + ", allowed: " + allowed);

        return allowed;
    }
}