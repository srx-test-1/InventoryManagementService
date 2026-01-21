package org.example;

import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * Service for managing inventory operations with secure URL handling.
 * Implements protection against CVE-2024-22243 (Open Redirect/SSRF).
 */
@Service
public class InventoryManagementService {
    
    // Allowlist of trusted hosts for redirect operations
    private static final Set<String> ALLOWED_HOSTS = new HashSet<>(Arrays.asList(
        "localhost",
        "127.0.0.1",
        "inventory.example.com",
        "api.inventory.example.com"
    ));
    
    /**
     * Builds a redirect URL with host validation to prevent open redirect attacks.
     * 
     * @param url The URL to validate and build
     * @return The validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI buildRedirectUrl(String url) {
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }
        
        // Use UriComponentsBuilder to parse the URL
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(url);
        URI uri = builder.build().toUri();
        
        // Validate the host against the allowlist
        String host = uri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted redirect host: " + host);
        }
        
        return uri;
    }
    
    /**
     * Builds an API endpoint URL with host validation to prevent SSRF attacks.
     * 
     * @param baseUrl The base URL for the API endpoint
     * @param path The path to append
     * @return The validated URI
     * @throws IllegalArgumentException if the host is not in the allowlist
     */
    public URI buildApiUrl(String baseUrl, String path) {
        if (baseUrl == null || baseUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Base URL cannot be null or empty");
        }
        
        // Build the URL with the provided path
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl).path(path);
        URI uri = builder.build().toUri();
        
        // Validate the host against the allowlist
        String host = uri.getHost();
        if (host == null || !ALLOWED_HOSTS.contains(host)) {
            throw new IllegalArgumentException("Untrusted API host: " + host);
        }
        
        return uri;
    }
    
    /**
     * Checks if a host is in the allowlist.
     * 
     * @param host The host to check
     * @return true if the host is allowed, false otherwise
     */
    public boolean isHostAllowed(String host) {
        return host != null && ALLOWED_HOSTS.contains(host);
    }
}
