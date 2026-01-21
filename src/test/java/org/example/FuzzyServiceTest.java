package org.example;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for FuzzyService to verify protection against CVE-2024-22243.
 * Tests cover open redirect and SSRF attack scenarios.
 */
class FuzzyServiceTest {
    
    private FuzzyService service;
    
    @BeforeEach
    void setUp() {
        service = new FuzzyService();
    }
    
    // Tests for buildSearchUrl
    
    @Test
    void testBuildSearchUrl_WithAllowedHost_Success() {
        String url = "http://localhost:8080/search";
        URI result = service.buildSearchUrl(url);
        
        assertNotNull(result);
        assertEquals("localhost", result.getHost());
        assertEquals("/search", result.getPath());
    }
    
    @Test
    void testBuildSearchUrl_WithAllowedSearchHost_Success() {
        String url = "https://search.example.com/fuzzy";
        URI result = service.buildSearchUrl(url);
        
        assertNotNull(result);
        assertEquals("search.example.com", result.getHost());
        assertEquals("/fuzzy", result.getPath());
    }
    
    @Test
    void testBuildSearchUrl_WithUntrustedHost_ThrowsException() {
        String url = "http://malicious.com/evil-search";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildSearchUrl(url)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted search host"));
    }
    
    @Test
    void testBuildSearchUrl_OpenRedirectAttempt_ThrowsException() {
        String url = "http://attacker.com/redirect?to=phishing";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildSearchUrl(url)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted search host"));
    }
    
    @Test
    void testBuildSearchUrl_WithNullUrl_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildSearchUrl(null)
        );
        
        assertTrue(exception.getMessage().contains("URL cannot be null or empty"));
    }
    
    @Test
    void testBuildSearchUrl_WithEmptyUrl_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildSearchUrl("   ")
        );
        
        assertTrue(exception.getMessage().contains("URL cannot be null or empty"));
    }
    
    // Tests for buildQueryUrl
    
    @Test
    void testBuildQueryUrl_WithAllowedHost_Success() {
        String baseUrl = "http://localhost:8080";
        String queryParam = "q";
        String queryValue = "test";
        
        URI result = service.buildQueryUrl(baseUrl, queryParam, queryValue);
        
        assertNotNull(result);
        assertEquals("localhost", result.getHost());
        assertTrue(result.getQuery().contains("q=test"));
    }
    
    @Test
    void testBuildQueryUrl_WithAllowedApiHost_Success() {
        String baseUrl = "https://api.search.example.com";
        String queryParam = "query";
        String queryValue = "fuzzy search";
        
        URI result = service.buildQueryUrl(baseUrl, queryParam, queryValue);
        
        assertNotNull(result);
        assertEquals("api.search.example.com", result.getHost());
        assertNotNull(result.getQuery());
    }
    
    @Test
    void testBuildQueryUrl_WithUntrustedHost_ThrowsException() {
        String baseUrl = "http://internal.network.local";
        String queryParam = "param";
        String queryValue = "value";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl(baseUrl, queryParam, queryValue)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted query host"));
    }
    
    @Test
    void testBuildQueryUrl_SSRFAttemptToCloudMetadata_ThrowsException() {
        // Simulating SSRF attack to cloud provider metadata endpoint
        String baseUrl = "http://169.254.169.254";
        String queryParam = "path";
        String queryValue = "/latest/meta-data/iam/security-credentials";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl(baseUrl, queryParam, queryValue)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted query host"));
    }
    
    @Test
    void testBuildQueryUrl_SSRFAttemptToInternalService_ThrowsException() {
        // Simulating SSRF attack to internal service
        String baseUrl = "http://192.168.1.1";
        String queryParam = "cmd";
        String queryValue = "admin";
        
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl(baseUrl, queryParam, queryValue)
        );
        
        assertTrue(exception.getMessage().contains("Untrusted query host"));
    }
    
    @Test
    void testBuildQueryUrl_WithNullBaseUrl_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl(null, "param", "value")
        );
        
        assertTrue(exception.getMessage().contains("Base URL cannot be null or empty"));
    }
    
    @Test
    void testBuildQueryUrl_WithNullQueryParam_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl("http://localhost:8080", null, "value")
        );
        
        assertTrue(exception.getMessage().contains("Query parameter name cannot be null or empty"));
    }
    
    @Test
    void testBuildQueryUrl_WithEmptyQueryParam_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl("http://localhost:8080", "  ", "value")
        );
        
        assertTrue(exception.getMessage().contains("Query parameter name cannot be null or empty"));
    }
    
    @Test
    void testBuildQueryUrl_WithNullQueryValue_ThrowsException() {
        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> service.buildQueryUrl("http://localhost:8080", "param", null)
        );
        
        assertTrue(exception.getMessage().contains("Query parameter value cannot be null"));
    }
    
    // Tests for validateCallbackUrl
    
    @Test
    void testValidateCallbackUrl_WithAllowedHost_ReturnsTrue() {
        String callbackUrl = "http://localhost:8080/callback";
        assertTrue(service.validateCallbackUrl(callbackUrl));
    }
    
    @Test
    void testValidateCallbackUrl_WithAllowedSearchHost_ReturnsTrue() {
        String callbackUrl = "https://search.example.com/callback";
        assertTrue(service.validateCallbackUrl(callbackUrl));
    }
    
    @Test
    void testValidateCallbackUrl_WithUntrustedHost_ReturnsFalse() {
        String callbackUrl = "http://malicious.com/callback";
        assertFalse(service.validateCallbackUrl(callbackUrl));
    }
    
    @Test
    void testValidateCallbackUrl_OpenRedirectAttempt_ReturnsFalse() {
        String callbackUrl = "http://attacker.net/steal-credentials";
        assertFalse(service.validateCallbackUrl(callbackUrl));
    }
    
    @Test
    void testValidateCallbackUrl_WithNullUrl_ReturnsFalse() {
        assertFalse(service.validateCallbackUrl(null));
    }
    
    @Test
    void testValidateCallbackUrl_WithEmptyUrl_ReturnsFalse() {
        assertFalse(service.validateCallbackUrl("   "));
    }
    
    @Test
    void testValidateCallbackUrl_WithMalformedUrl_ReturnsFalse() {
        String callbackUrl = "not-a-valid-url";
        assertFalse(service.validateCallbackUrl(callbackUrl));
    }
}
