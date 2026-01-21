package org.example;

import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Service for fuzzy search operations with secure URL handling.
 * Implements protection against CVE-2024-22243 (Open Redirect/SSRF).
 */
@Service
public class FuzzyService {
    
    // Allowlist of trusted hosts for external service calls
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
        "localhost",
        "127.0.0.1",
        "search.example.com",
        "api.search.example.com"
    ));
    
    /**
     * Builds a search URL with host validation to prevent open redirect attacks.
     * 
     * @param url The URL to validate and build
     * @return The validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI buildSearchUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }
        
        // Use UriComponentsBuilder to parse the URL
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        URI uri = builder.build().toUri();
        
        // Validate the host against the allowlist
        String host = uri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted search host: " + host);
        }
        
        return uri;
    }
    
    /**
     * Builds a query URL with parameters and host validation to prevent SSRF attacks.
     * 
     * @param baseUrl The base URL for the query
     * @param queryParam The query parameter name
     * @param queryValue The query parameter value
     * @return The validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI buildQueryUrl(String baseUrl, String queryParam, String queryValue) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Base URL cannot be null or empty");
        }
        
        // Build the URL with query parameters
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl)
            .queryParam(queryParam, queryValue);
        URI uri = builder.build().toUri();
        
        // Validate the host against the allowlist
        String host = uri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted query host: " + host);
        }
        
        return uri;
    }
    
    /**
     * Validates a callback URL to ensure it's safe for redirect.
     * 
     * @param callbackUrl The callback URL to validate
     * @return true if valid and safe, false otherwise
     */
    public boolean validateCallbackUrl(String callbackUrl) {
        if (callbackUrl == null || callbackUrl.trim().isEmpty()) {
            return false;
        }
        
        try {
            UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(callbackUrl);
            URI uri = builder.build().toUri();
            String host = uri.getHost();
            return host != null && ALLOWED_HOSTS.contains(host);
        } catch (Exception e) {
            return false;
        }
    }
}
