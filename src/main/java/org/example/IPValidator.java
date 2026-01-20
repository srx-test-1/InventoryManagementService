package org.example;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

/**
 * IP Validator utility to mitigate SSRF vulnerabilities (CVE-2024-29415)
 * 
 * This class provides validation for IP addresses to ensure that malformed
 * or deceptive IP addresses are properly identified as non-public to prevent
 * Server-Side Request Forgery (SSRF) attacks.
 */
public class IPValidator {
    
    // Pattern to detect octal notation in IP addresses (e.g., 012.1.2.3)
    private static final Pattern OCTAL_PATTERN = Pattern.compile("^0\\d+");
    
    // Pattern to detect short form IPv4 (e.g., 127.1 instead of 127.0.0.1)
    private static final Pattern SHORT_IPV4_PATTERN = Pattern.compile("^\\d+\\.\\d+$");
    
    // Pattern to detect IPv6 addresses (basic check)
    private static final Pattern IPV6_PATTERN = Pattern.compile("^[0-9a-fA-F:]+$");
    
    // Pattern to extract IPv4 from IPv6-mapped addresses (::ffff:x.x.x.x)
    private static final Pattern IPV6_MAPPED_IPV4_PATTERN = Pattern.compile("::ffff:(\\d+\\.\\d+\\.\\d+\\.\\d+)$");
    
    /**
     * Checks if an IP address is public.
     * 
     * This method mitigates CVE-2024-29415 by explicitly checking for:
     * - Malformed IPv4 addresses like 127.1, 127.0.1
     * - Octal notation IPv4 addresses like 012.1.2.3
     * - IPv6 addresses that map to loopback like ::ffff:127.0.0.1
     * - Standard private IP ranges
     * - Loopback addresses
     * 
     * @param ipAddress The IP address string to validate
     * @return true if the IP is public, false if it's private/loopback/invalid
     */
    public static boolean isPublic(String ipAddress) {
        if (ipAddress == null || ipAddress.trim().isEmpty()) {
            return false;
        }
        
        // Normalize the input (null check already done above)
        String normalizedIp = ipAddress.trim();
        if (normalizedIp.isEmpty()) {
            return false;
        }
        normalizedIp = normalizedIp.toLowerCase();
        
        // Check for short form IPv4 addresses (e.g., 127.1)
        // These should be treated as non-public to prevent SSRF
        if (SHORT_IPV4_PATTERN.matcher(normalizedIp).matches()) {
            return false;
        }
        
        // Check for octal notation in IPv4 (e.g., 012.1.2.3)
        // Split by dots to check each octet
        String[] parts = normalizedIp.split("\\.");
        for (String part : parts) {
            if (OCTAL_PATTERN.matcher(part).matches()) {
                // Octal notation detected - treat as non-public
                return false;
            }
        }
        
        // Check for IPv6 addresses that map to IPv4 loopback
        // e.g., ::ffff:127.0.0.1 or ::1
        // Only process if it looks like an IPv6 address (contains : and no invalid chars for IPv6)
        if (normalizedIp.contains(":") && IPV6_PATTERN.matcher(normalizedIp.replaceAll("[\\[\\]]", "")).find()) {
            // Remove brackets if present (e.g., [::1])
            String cleanedIp = normalizedIp.replaceAll("[\\[\\]]", "");
            
            // Check for IPv6 loopback
            if (cleanedIp.equals("::1") || cleanedIp.startsWith("::1/")) {
                return false;
            }
            
            // Check for IPv4-mapped IPv6 addresses pointing to loopback/private
            // Use regex pattern matching for more robust extraction
            java.util.regex.Matcher matcher = IPV6_MAPPED_IPV4_PATTERN.matcher(cleanedIp);
            if (matcher.find()) {
                // Extract the IPv4 part using the captured group
                String ipv4Part = matcher.group(1);
                // Recursively check if the IPv4 part is public
                return isPublic(ipv4Part);
            }
            
            // Check for link-local and private IPv6 ranges
            if (normalizedIp.startsWith("fe80:") || // Link-local
                normalizedIp.startsWith("fc00:") || // Unique local
                normalizedIp.startsWith("fd00:")) {  // Unique local
                return false;
            }
        }
        
        try {
            InetAddress inetAddress = InetAddress.getByName(normalizedIp);
            
            // Check for loopback addresses
            if (inetAddress.isLoopbackAddress()) {
                return false;
            }
            
            // Check for site-local (private) addresses
            if (inetAddress.isSiteLocalAddress()) {
                return false;
            }
            
            // Check for link-local addresses
            if (inetAddress.isLinkLocalAddress()) {
                return false;
            }
            
            // Check for any-local address (0.0.0.0)
            if (inetAddress.isAnyLocalAddress()) {
                return false;
            }
            
            // Additional explicit checks for private IPv4 ranges
            byte[] addr = inetAddress.getAddress();
            
            // For IPv4 addresses
            if (addr.length == 4) {
                int firstOctet = addr[0] & 0xff;
                int secondOctet = addr[1] & 0xff;
                
                // 10.0.0.0/8
                if (firstOctet == 10) {
                    return false;
                }
                
                // 172.16.0.0/12
                if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31) {
                    return false;
                }
                
                // 192.168.0.0/16
                if (firstOctet == 192 && secondOctet == 168) {
                    return false;
                }
                
                // 127.0.0.0/8 (additional loopback check)
                if (firstOctet == 127) {
                    return false;
                }
                
                // 169.254.0.0/16 (link-local)
                if (firstOctet == 169 && secondOctet == 254) {
                    return false;
                }
            }
            
            // If none of the above checks matched, consider it public
            return true;
            
        } catch (UnknownHostException e) {
            // If we can't resolve the address, treat it as non-public for safety
            return false;
        }
    }
    
    /**
     * Validates if an IP address is safe to use (i.e., not susceptible to SSRF)
     * 
     * @param ipAddress The IP address to validate
     * @return true if the IP is safe (public), false if it could be used for SSRF
     */
    public static boolean isSafeForExternalRequest(String ipAddress) {
        return isPublic(ipAddress);
    }
}
