package org.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for InventoryManagementService to verify protection against CVE-2024-22243.
 * Tests cover open redirect and SSRF attack scenarios.
 */
class InventoryManagementServiceTest {
    
    private InventoryManagementService service;
    
    @BeforeEach
    void setUp() {
        service = new InventoryManagementService();
    }
    
    // Tests for buildRedirectUrl
    
    @Test
    void testBuildRedirectUrl_WithAllowedHost_Success() {
        String url = "http://localhost:8080/redirect";
        URI result = service.buildRedirectUrl(url);
        
        assertNotNull(result);
        assertEquals("localhost", result.getHost());
        assertEquals("/redirect", result.getPath());
    }
    
    @Test
    void testBuildRedirectUrl_WithAllowedInventoryHost_Success() {
        String url = "https://inventory.example.com/api/items";
        URI result = service.buildRedirectUrl(url);
        
        assertNotNull(result);
        assertEquals("inventory.example.com", result.getHost());
        assertEquals("/api/items", result.getPath());
    }
    
    @Test
    void testBuildRedirectUrl_WithUntrustedHost_ThrowsException() {
        String url = "http://malicious.com/steal-data";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildRedirectUrl(url)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted redirect host"));
    }
    
    @Test
    void testBuildRedirectUrl_WithExternalHost_ThrowsException() {
        String url = "http://evil.attacker.com/phishing";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildRedirectUrl(url)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted redirect host"));
    }
    
    @Test
    void testBuildRedirectUrl_WithNullUrl_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildRedirectUrl(null)
        );
        
        assertTrue(exception.getMessage().contains("URL cannot be null or empty"));
    }
    
    @Test
    void testBuildRedirectUrl_WithEmptyUrl_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildRedirectUrl("   ")
        );
        
        assertTrue(exception.getMessage().contains("URL cannot be null or empty"));
    }
    
    // Tests for buildApiUrl
    
    @Test
    void testBuildApiUrl_WithAllowedHost_Success() {
        String baseUrl = "http://localhost:8080";
        String path = "/api/inventory";
        
        URI result = service.buildApiUrl(baseUrl, path);
        
        assertNotNull(result);
        assertEquals("localhost", result.getHost());
        assertTrue(result.getPath().contains("/api/inventory"));
    }
    
    @Test
    void testBuildApiUrl_WithAllowedApiHost_Success() {
        String baseUrl = "https://api.inventory.example.com";
        String path = "/v1/products";
        
        URI result = service.buildApiUrl(baseUrl, path);
        
        assertNotNull(result);
        assertEquals("api.inventory.example.com", result.getHost());
        assertTrue(result.getPath().contains("/v1/products"));
    }
    
    @Test
    void testBuildApiUrl_WithUntrustedHost_ThrowsException() {
        String baseUrl = "http://internal.server.local";
        String path = "/admin/secrets";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildApiUrl(baseUrl, path)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted API host"));
    }
    
    @Test
    void testBuildApiUrl_SSRFAttempt_ThrowsException() {
        // Simulating SSRF attack to internal metadata service
        String baseUrl = "http://169.254.169.254";
        String path = "/latest/meta-data";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildApiUrl(baseUrl, path)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted API host"));
    }
    
    @Test
    void testBuildApiUrl_WithNullBaseUrl_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildApiUrl(null, "/api/test")
        );
        
        assertTrue(exception.getMessage().contains("Base URL cannot be null or empty"));
    }
    
    // Tests for isHostAllowed
    
    @Test
    void testIsHostAllowed_WithAllowedHost_ReturnsTrue() {
        assertTrue(service.isHostAllowed("localhost"));
        assertTrue(service.isHostAllowed("127.0.0.1"));
        assertTrue(service.isHostAllowed("inventory.example.com"));
        assertTrue(service.isHostAllowed("api.inventory.example.com"));
    }
    
    @Test
    void testIsHostAllowed_WithUntrustedHost_ReturnsFalse() {
        assertFalse(service.isHostAllowed("evil.com"));
        assertFalse(service.isHostAllowed("attacker.net"));
        assertFalse(service.isHostAllowed("169.254.169.254"));
    }
    
    @Test
    void testIsHostAllowed_WithNullHost_ReturnsFalse() {
        assertFalse(service.isHostAllowed(null));
    }
}
