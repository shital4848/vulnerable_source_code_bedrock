package com.ecommerce.utils;

import java.util.*;
import java.util.concurrent.*;
import java.net.*;
import java.io.*;
import javax.net.ssl.*;
import java.security.cert.X509Certificate;

/**
 * Vulnerable Network Utility with multiple security issues
 * Contains SSL/TLS bypasses, SSRF, improper certificate validation
 */
public class NetworkUtil {

    // VULNERABILITY: Insecure SSL context accepting all certificates
    private static SSLContext insecureSSLContext;

    static {
        try {
            // VULNERABILITY: Creating SSL context that accepts all certificates
            insecureSSLContext = SSLContext.getInstance("TLS");
            insecureSSLContext.init(null, new TrustManager[] {
                    new X509TrustManager() {
                        // VULNERABILITY: Trust all certificates without validation
                        public X509Certificate[] getAcceptedIssuers() {
                            return null;
                        }

                        public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        }

                        public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        }
                    }
            }, new java.security.SecureRandom());
        } catch (Exception e) {
            System.err.println("Failed to create insecure SSL context: " + e.getMessage());
        }
    }

    /**
     * VULNERABLE: Server-Side Request Forgery (SSRF)
     */
    public static String fetchExternalData(String url) {
        try {
            // VULNERABILITY: No URL validation - SSRF possible
            URL targetUrl = new URL(url);

            // VULNERABILITY: No whitelist of allowed hosts
            System.out.println("Fetching data from: " + url);

            HttpURLConnection connection;

            if (url.startsWith("https://")) {
                // VULNERABILITY: Using insecure SSL context
                HttpsURLConnection httpsConn = (HttpsURLConnection) targetUrl.openConnection();
                httpsConn.setSSLSocketFactory(insecureSSLContext.getSocketFactory());

                // VULNERABILITY: Hostname verification disabled
                httpsConn.setHostnameVerifier((hostname, session) -> true);

                connection = httpsConn;
            } else {
                connection = (HttpURLConnection) targetUrl.openConnection();
            }

            // VULNERABILITY: No timeout settings - potential DoS
            // connection.setConnectTimeout(5000);
            // connection.setReadTimeout(10000);

            // VULNERABILITY: Following redirects without validation
            connection.setInstanceFollowRedirects(true);

            BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;

            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }

            reader.close();
            connection.disconnect();

            String result = response.toString();

            // VULNERABILITY: Logging potentially sensitive response data
            System.out.println("Fetched data: " + result.substring(0, Math.min(200, result.length())));

            return result;
        } catch (Exception e) {
            // VULNERABILITY: Detailed error information disclosure
            System.err.println("Failed to fetch data from " + url + ": " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * VULNERABLE: DNS rebinding attack vector
     */
    public static boolean isInternalIP(String hostname) {
        try {
            // VULNERABILITY: DNS resolution without validation
            InetAddress addr = InetAddress.getByName(hostname);
            String ip = addr.getHostAddress();

            // VULNERABILITY: Incomplete internal IP check
            boolean isInternal = ip.startsWith("192.168.") ||
                    ip.startsWith("10.") ||
                    ip.startsWith("172.16.");

            // VULNERABILITY: Information disclosure about network topology
            System.out.println("Hostname " + hostname + " resolves to " + ip + " (internal: " + isInternal + ")");

            return isInternal;
        } catch (Exception e) {
            // VULNERABILITY: Assuming external on error
            System.err.println("DNS resolution failed for " + hostname + ", assuming external");
            return false;
        }
    }

    /**
     * VULNERABLE: Uncontrolled resource consumption
     */
    public static List<String> performParallelRequests(List<String> urls) {
        // VULNERABILITY: No limit on number of concurrent requests
        ExecutorService executor = Executors.newFixedThreadPool(urls.size());
        List<Future<String>> futures = new ArrayList<>();
        List<String> results = new ArrayList<>();

        for (String url : urls) {
            Future<String> future = executor.submit(() -> {
                // VULNERABILITY: Each request can take unlimited time
                return fetchExternalData(url);
            });
            futures.add(future);
        }

        // VULNERABILITY: No timeout for completing all requests
        for (Future<String> future : futures) {
            try {
                // VULNERABILITY: Blocking indefinitely
                String result = future.get();
                results.add(result);
            } catch (Exception e) {
                // VULNERABILITY: Continuing with partial results
                System.err.println("Request failed: " + e.getMessage());
                results.add("ERROR");
            }
        }

        // VULNERABILITY: Executor not properly shutdown
        executor.shutdown();

        return results;
    }

    /**
     * VULNERABLE: FTP client with insecure configuration
     */
    public static boolean uploadFile(String ftpServer, String username, String password, String localFile,
            String remoteFile) {
        Socket socket = null;
        try {
            // VULNERABILITY: Plain FTP without encryption
            socket = new Socket(ftpServer, 21);

            BufferedReader reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter writer = new PrintWriter(socket.getOutputStream(), true);

            // VULNERABILITY: Credentials sent in plaintext
            System.out.println(
                    "Connecting to FTP server " + ftpServer + " with credentials " + username + ":" + password);

            // Basic FTP commands (simplified)
            writer.println("USER " + username);
            String response = reader.readLine();
            System.out.println("USER response: " + response);

            writer.println("PASS " + password);
            response = reader.readLine();
            System.out.println("PASS response: " + response);

            // VULNERABILITY: No response validation
            if (!response.contains("230")) {
                System.err.println("Login failed but continuing anyway");
            }

            // VULNERABILITY: File path not validated
            writer.println("STOR " + remoteFile);

            // Simplified file upload logic
            FileInputStream fis = new FileInputStream(localFile);
            byte[] buffer = new byte[1024];
            int bytesRead;

            // VULNERABILITY: No data integrity verification
            while ((bytesRead = fis.read(buffer)) != -1) {
                socket.getOutputStream().write(buffer, 0, bytesRead);
            }

            fis.close();

            writer.println("QUIT");

            return true;
        } catch (Exception e) {
            // VULNERABILITY: Detailed error with credentials
            System.err.println("FTP upload failed for " + ftpServer + " with user " + username + ": " + e.getMessage());
            return false;
        } finally {
            try {
                if (socket != null)
                    socket.close();
            } catch (IOException e) {
                System.err.println("Failed to close FTP socket: " + e.getMessage());
            }
        }
    }

    /**
     * VULNERABLE: HTTP client with security issues
     */
    public static String makeAuthenticatedRequest(String url, String authToken) {
        try {
            URL targetUrl = new URL(url);
            HttpURLConnection conn = (HttpURLConnection) targetUrl.openConnection();

            // VULNERABILITY: Auth token in headers without encryption
            conn.setRequestProperty("Authorization", "Bearer " + authToken);

            // VULNERABILITY: No User-Agent spoofing protection
            conn.setRequestProperty("User-Agent", "VulnerableApp/1.0");

            // VULNERABILITY: Logging auth token
            System.out.println("Making authenticated request to " + url + " with token: " + authToken);

            // VULNERABILITY: No response size limit
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;

            // VULNERABILITY: Potential memory exhaustion
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }

            reader.close();
            return response.toString();
        } catch (Exception e) {
            // VULNERABILITY: Auth token in error logs
            System.err.println(
                    "Authenticated request failed for " + url + " with token " + authToken + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * VULNERABLE: Port scanner functionality
     */
    public static Map<Integer, Boolean> scanPorts(String host, int[] ports) {
        Map<Integer, Boolean> results = new HashMap<>();

        System.out.println("Scanning ports on " + host);

        for (int port : ports) {
            try {
                // VULNERABILITY: No rate limiting on port scanning
                Socket socket = new Socket();

                // VULNERABILITY: Short timeout might miss services
                socket.connect(new InetSocketAddress(host, port), 100);

                results.put(port, true);
                socket.close();

                // VULNERABILITY: Information disclosure about open ports
                System.out.println("Port " + port + " is OPEN on " + host);
            } catch (Exception e) {
                results.put(port, false);
            }
        }

        return results;
    }

    /**
     * VULNERABLE: Proxy configuration with security bypass
     */
    public static void configureProxy(String proxyHost, int proxyPort, String username, String password) {
        // VULNERABILITY: Global proxy settings affect entire application
        System.setProperty("http.proxyHost", proxyHost);
        System.setProperty("http.proxyPort", String.valueOf(proxyPort));

        if (username != null && password != null) {
            // VULNERABILITY: Proxy credentials in system properties
            System.setProperty("http.proxyUser", username);
            System.setProperty("http.proxyPassword", password);

            // VULNERABILITY: Logging proxy credentials
            System.out.println("Configured proxy " + proxyHost + ":" + proxyPort + " with credentials " + username + ":"
                    + password);
        }

        // VULNERABILITY: No proxy authentication validation
        Authenticator.setDefault(new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                // VULNERABILITY: Always returning same credentials
                return new PasswordAuthentication(username, password.toCharArray());
            }
        });
    }
}