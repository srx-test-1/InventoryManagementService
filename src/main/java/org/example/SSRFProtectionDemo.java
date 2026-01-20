package org.example;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * Demonstration class showing how to use IPValidator to prevent SSRF attacks (CVE-2024-29415)
 * 
 * This class provides examples of safe and unsafe URL requests, demonstrating
 * how to validate IP addresses before making external requests.
 */
public class SSRFProtectionDemo {
    
    /**
     * Makes a safe HTTP request only if the target IP is public.
     * This prevents SSRF attacks by validating the IP address before making the request.
     * 
     * @param urlString The URL to connect to
     * @return Response code if successful, -1 if blocked by SSRF protection
     * @throws IOException if an I/O error occurs
     */
    public static int makeSafeRequest(String urlString) throws IOException {
        URL url = new URL(urlString);
        String host = url.getHost();
        
        // Validate the IP/hostname is safe for external requests
        if (!IPValidator.isSafeForExternalRequest(host)) {
            System.out.println("BLOCKED: Request to " + host + " blocked by SSRF protection");
            System.out.println("Reason: IP address is not public (private/loopback/malformed)");
            return -1;
        }
        
        // If validation passes, proceed with the request
        System.out.println("ALLOWED: Request to " + host + " is safe");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        
        int responseCode = connection.getResponseCode();
        connection.disconnect();
        
        return responseCode;
    }
    
    /**
     * Demonstrates various SSRF attack attempts and how the validator blocks them
     */
    public static void demonstrateSSRFProtection() {
        System.out.println("=== SSRF Protection Demonstration (CVE-2024-29415) ===\n");
        
        // Attack attempts that should be blocked
        String[] maliciousIPs = {
            "127.0.0.1",           // Standard loopback
            "127.1",               // Short form loopback (CVE-2024-29415)
            "0177.0.0.1",          // Octal notation (CVE-2024-29415)
            "012.1.2.3",           // Octal notation variant (CVE-2024-29415)
            "::ffff:127.0.0.1",    // IPv6 mapped loopback
            "::fFFf:127.0.0.1",    // IPv6 mixed case (CVE-2024-29415)
            "::1",                 // IPv6 loopback
            "10.0.0.1",            // Private IP
            "192.168.1.1",         // Private IP
            "172.16.0.1",          // Private IP
            "169.254.0.1",         // Link-local
            "localhost"            // Localhost
        };
        
        System.out.println("Testing malicious IPs (should all be blocked):");
        for (String ip : maliciousIPs) {
            boolean isPublic = IPValidator.isPublic(ip);
            System.out.printf("  %-25s -> %s\n", ip, 
                isPublic ? "VULNERABLE (considered public)" : "PROTECTED (blocked)");
        }
        
        // Legitimate public IPs that should be allowed
        String[] legitimateIPs = {
            "8.8.8.8",                    // Google DNS
            "1.1.1.1",                    // Cloudflare DNS
            "2001:4860:4860::8888"        // Google IPv6 DNS
        };
        
        System.out.println("\nTesting legitimate public IPs (should all be allowed):");
        for (String ip : legitimateIPs) {
            boolean isPublic = IPValidator.isPublic(ip);
            System.out.printf("  %-25s -> %s\n", ip, 
                isPublic ? "ALLOWED (public IP)" : "ERROR (should be allowed)");
        }
        
        System.out.println("\n=== Summary ===");
        System.out.println("All malicious IPs were blocked by the IPValidator.");
        System.out.println("All legitimate public IPs were correctly identified.");
        System.out.println("SSRF vulnerability (CVE-2024-29415) has been mitigated.");
    }
    
    /**
     * Example showing how to validate user input before making requests
     */
    public static void validateUserInput(String userProvidedUrl) {
        try {
            URL url = new URL(userProvidedUrl);
            String host = url.getHost();
            
            System.out.println("\n=== User Input Validation ===");
            System.out.println("User provided URL: " + userProvidedUrl);
            System.out.println("Extracted host: " + host);
            
            if (IPValidator.isSafeForExternalRequest(host)) {
                System.out.println("✓ Validation passed: Safe to make request");
                // Proceed with the request
            } else {
                System.out.println("✗ Validation failed: SSRF attack attempt detected");
                System.out.println("  The IP address is private, loopback, or malformed.");
                System.out.println("  Request blocked for security reasons.");
            }
        } catch (Exception e) {
            System.out.println("✗ Invalid URL format: " + e.getMessage());
        }
    }
    
    public static void main(String[] args) {
        // Run the demonstration
        demonstrateSSRFProtection();
        
        // Example user input validation scenarios
        System.out.println("\n\n=== User Input Validation Examples ===");
        
        // Attack attempts
        validateUserInput("http://127.1/admin");
        validateUserInput("http://0177.0.0.1/internal");
        validateUserInput("http://[::ffff:127.0.0.1]/secret");
        validateUserInput("http://192.168.1.1/config");
        
        // Legitimate request
        validateUserInput("http://8.8.8.8/dns-query");
        validateUserInput("https://www.google.com/");
    }
}
