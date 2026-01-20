package org.example;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for IPValidator to ensure SSRF vulnerability mitigation (CVE-2024-29415)
 */
public class IPValidatorTest {
    
    // Tests for CVE-2024-29415 specific cases
    
    @Test
    public void testShortFormLoopback_127_1() {
        // Short form IPv4 addresses like 127.1 should be treated as non-public
        assertFalse(IPValidator.isPublic("127.1"), 
            "Short form loopback 127.1 should not be considered public");
    }
    
    @Test
    public void testShortFormLoopback_127_0_1() {
        // Another short form variant
        assertFalse(IPValidator.isPublic("127.0.1"), 
            "Short form loopback 127.0.1 should not be considered public");
    }
    
    @Test
    public void testOctalNotation_012_1_2_3() {
        // Octal notation like 012.1.2.3 should be treated as non-public
        assertFalse(IPValidator.isPublic("012.1.2.3"), 
            "Octal notation 012.1.2.3 should not be considered public");
    }
    
    @Test
    public void testOctalNotation_0177_0_0_1() {
        // Octal notation for 127.0.0.1 (0177.0.0.1)
        assertFalse(IPValidator.isPublic("0177.0.0.1"), 
            "Octal notation 0177.0.0.1 should not be considered public");
    }
    
    @Test
    public void testIPv6MappedLoopback_lowercase() {
        // IPv6 mapped IPv4 loopback ::ffff:127.0.0.1
        assertFalse(IPValidator.isPublic("::ffff:127.0.0.1"), 
            "IPv6 mapped loopback ::ffff:127.0.0.1 should not be considered public");
    }
    
    @Test
    public void testIPv6MappedLoopback_uppercase() {
        // IPv6 mapped IPv4 loopback with uppercase ::FFFF:127.0.0.1
        assertFalse(IPValidator.isPublic("::FFFF:127.0.0.1"), 
            "IPv6 mapped loopback ::FFFF:127.0.0.1 should not be considered public");
    }
    
    @Test
    public void testIPv6MappedLoopback_mixedCase() {
        // IPv6 mapped IPv4 loopback with mixed case ::fFFf:127.0.0.1
        assertFalse(IPValidator.isPublic("::fFFf:127.0.0.1"), 
            "IPv6 mapped loopback ::fFFf:127.0.0.1 should not be considered public");
    }
    
    // Standard loopback tests
    
    @Test
    public void testStandardLoopback_127_0_0_1() {
        assertFalse(IPValidator.isPublic("127.0.0.1"), 
            "Standard loopback 127.0.0.1 should not be considered public");
    }
    
    @Test
    public void testStandardLoopback_localhost() {
        assertFalse(IPValidator.isPublic("localhost"), 
            "Localhost should not be considered public");
    }
    
    @Test
    public void testIPv6Loopback() {
        assertFalse(IPValidator.isPublic("::1"), 
            "IPv6 loopback ::1 should not be considered public");
    }
    
    // Private IP range tests
    
    @Test
    public void testPrivateIP_10_0_0_1() {
        assertFalse(IPValidator.isPublic("10.0.0.1"), 
            "Private IP 10.0.0.1 should not be considered public");
    }
    
    @Test
    public void testPrivateIP_10_255_255_255() {
        assertFalse(IPValidator.isPublic("10.255.255.255"), 
            "Private IP 10.255.255.255 should not be considered public");
    }
    
    @Test
    public void testPrivateIP_192_168_1_1() {
        assertFalse(IPValidator.isPublic("192.168.1.1"), 
            "Private IP 192.168.1.1 should not be considered public");
    }
    
    @Test
    public void testPrivateIP_192_168_0_1() {
        assertFalse(IPValidator.isPublic("192.168.0.1"), 
            "Private IP 192.168.0.1 should not be considered public");
    }
    
    @Test
    public void testPrivateIP_172_16_0_1() {
        assertFalse(IPValidator.isPublic("172.16.0.1"), 
            "Private IP 172.16.0.1 should not be considered public");
    }
    
    @Test
    public void testPrivateIP_172_31_255_255() {
        assertFalse(IPValidator.isPublic("172.31.255.255"), 
            "Private IP 172.31.255.255 should not be considered public");
    }
    
    @Test
    public void testLinkLocal_169_254_0_1() {
        assertFalse(IPValidator.isPublic("169.254.0.1"), 
            "Link-local IP 169.254.0.1 should not be considered public");
    }
    
    // IPv6 private address tests
    
    @Test
    public void testIPv6LinkLocal() {
        assertFalse(IPValidator.isPublic("fe80::1"), 
            "IPv6 link-local fe80::1 should not be considered public");
    }
    
    @Test
    public void testIPv6UniqueLocal_fc00() {
        assertFalse(IPValidator.isPublic("fc00::1"), 
            "IPv6 unique local fc00::1 should not be considered public");
    }
    
    @Test
    public void testIPv6UniqueLocal_fd00() {
        assertFalse(IPValidator.isPublic("fd00::1"), 
            "IPv6 unique local fd00::1 should not be considered public");
    }
    
    // IPv6 mapped private IPs
    
    @Test
    public void testIPv6MappedPrivate_10_0_0_1() {
        assertFalse(IPValidator.isPublic("::ffff:10.0.0.1"), 
            "IPv6 mapped private IP ::ffff:10.0.0.1 should not be considered public");
    }
    
    @Test
    public void testIPv6MappedPrivate_192_168_1_1() {
        assertFalse(IPValidator.isPublic("::ffff:192.168.1.1"), 
            "IPv6 mapped private IP ::ffff:192.168.1.1 should not be considered public");
    }
    
    // Public IP tests (should return true)
    
    @Test
    public void testPublicIP_8_8_8_8() {
        assertTrue(IPValidator.isPublic("8.8.8.8"), 
            "Google DNS 8.8.8.8 should be considered public");
    }
    
    @Test
    public void testPublicIP_1_1_1_1() {
        assertTrue(IPValidator.isPublic("1.1.1.1"), 
            "Cloudflare DNS 1.1.1.1 should be considered public");
    }
    
    @Test
    public void testPublicIP_google_dns() {
        assertTrue(IPValidator.isPublic("8.8.4.4"), 
            "Google DNS 8.8.4.4 should be considered public");
    }
    
    @Test
    public void testPublicIPv6() {
        assertTrue(IPValidator.isPublic("2001:4860:4860::8888"), 
            "Google IPv6 DNS 2001:4860:4860::8888 should be considered public");
    }
    
    // Edge cases
    
    @Test
    public void testNullInput() {
        assertFalse(IPValidator.isPublic(null), 
            "Null input should not be considered public");
    }
    
    @Test
    public void testEmptyString() {
        assertFalse(IPValidator.isPublic(""), 
            "Empty string should not be considered public");
    }
    
    @Test
    public void testWhitespaceString() {
        assertFalse(IPValidator.isPublic("   "), 
            "Whitespace string should not be considered public");
    }
    
    @Test
    public void testInvalidIPFormat() {
        assertFalse(IPValidator.isPublic("not.an.ip.address"), 
            "Invalid IP format should not be considered public");
    }
    
    @Test
    public void testMalformedIP() {
        assertFalse(IPValidator.isPublic("256.256.256.256"), 
            "Malformed IP should not be considered public");
    }
    
    // Test the isSafeForExternalRequest method
    
    @Test
    public void testSafeForExternalRequest_publicIP() {
        assertTrue(IPValidator.isSafeForExternalRequest("8.8.8.8"), 
            "Public IP should be safe for external requests");
    }
    
    @Test
    public void testSafeForExternalRequest_privateIP() {
        assertFalse(IPValidator.isSafeForExternalRequest("192.168.1.1"), 
            "Private IP should not be safe for external requests (SSRF risk)");
    }
    
    @Test
    public void testSafeForExternalRequest_loopback() {
        assertFalse(IPValidator.isSafeForExternalRequest("127.0.0.1"), 
            "Loopback IP should not be safe for external requests (SSRF risk)");
    }
    
    @Test
    public void testSafeForExternalRequest_shortForm() {
        assertFalse(IPValidator.isSafeForExternalRequest("127.1"), 
            "Short form loopback should not be safe for external requests (SSRF risk)");
    }
    
    @Test
    public void testSafeForExternalRequest_octal() {
        assertFalse(IPValidator.isSafeForExternalRequest("0177.0.0.1"), 
            "Octal notation should not be safe for external requests (SSRF risk)");
    }
}
