/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.domain.claim.mapper.ClaimMapper;
import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.jwks.JwksLoaderFactory;
import de.cuioss.jwt.token.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import de.cuioss.jwt.token.security.SecurityEventCounter;
import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
import lombok.Value;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Configuration class for issuer settings.
 * It aggregates all information needed to validate a JWT token.
 * <p>
 * This class contains the issuer URL, expected audience, expected client ID,
 * configuration for JwksLoader and {@link AlgorithmPreferences}.
 * </p>
 * <p>
 * The JwksLoader is initialized through the {@link #initSecurityEventCounter(SecurityEventCounter)} method
 * and can be accessed through the {@link #getJwksLoader()} method.
 * </p>
 */
@Builder
@Value
public class IssuerConfig {

    // Static map to store JwksLoader instances for IssuerConfig objects
    private static final Map<IssuerConfig, JwksLoader> JWKS_LOADER_MAP = new HashMap<>();

    @NonNull
    String issuer;

    @Singular("expectedAudience")
    Set<String> expectedAudience;

    @Singular("expectedClientId")
    Set<String> expectedClientId;

    /**
     * Configuration for HTTP JwksLoader.
     * Used when jwksLoader is null to initialize a new JwksLoader.
     */
    HttpJwksLoaderConfig httpJwksLoaderConfig;

    /**
     * File path for file-based JwksLoader.
     * Used when jwksLoader is null to initialize a new JwksLoader.
     */
    String jwksFilePath;

    /**
     * JWKS content for in-memory JwksLoader.
     * Used when jwksLoader is null to initialize a new JwksLoader.
     */
    String jwksContent;


    @Builder.Default
    AlgorithmPreferences algorithmPreferences = new AlgorithmPreferences();

    /**
     * Custom claim mappers that take precedence over the default ones.
     * The key is the claim name, and the value is the mapper to use for that claim.
     */
    @Singular("claimMapper")
    Map<String, ClaimMapper> claimMappers;

    /**
     * Initializes the JwksLoader if it's not already initialized.
     * This method should be called by TokenFactory before using the JwksLoader.
     * It will initialize the JwksLoader based on the first available configuration in the following order:
     * 1. HTTP JwksLoader (httpJwksLoaderConfig)
     * 2. File JwksLoader (jwksFilePath)
     * 3. In-memory JwksLoader (jwksContent)
     *
     * @param securityEventCounter the counter for security events
     * @throws IllegalStateException if no configuration is present
     */
    public void initSecurityEventCounter(@NonNull SecurityEventCounter securityEventCounter) {
        // Check if we already have a JwksLoader for this IssuerConfig in the map
        if (JWKS_LOADER_MAP.containsKey(this)) {
            return;
        }

        JwksLoader loader;

        // Initialize JwksLoader based on the first available configuration
        if (httpJwksLoaderConfig != null) {
            loader = JwksLoaderFactory.createHttpLoader(httpJwksLoaderConfig, securityEventCounter);
        } else if (jwksFilePath != null) {
            loader = JwksLoaderFactory.createFileLoader(jwksFilePath, securityEventCounter);
        } else if (jwksContent != null) {
            loader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
        } else {
            // Throw exception if no configuration is present
            throw new IllegalStateException("No JwksLoader configuration is present. One of httpJwksLoaderConfig, jwksFilePath, or jwksContent must be provided");
        }

        // Store the JwksLoader in the map
        JWKS_LOADER_MAP.put(this, loader);
    }

    /**
     * Gets the JwksLoader for this IssuerConfig.
     * This method should be called after initSecurityEventCounter has been called.
     *
     * @return the JwksLoader for this IssuerConfig
     * @throws IllegalStateException if the JwksLoader has not been initialized
     */
    public JwksLoader getJwksLoader() {
        JwksLoader loader = JWKS_LOADER_MAP.get(this);
        if (loader == null) {
            throw new IllegalStateException("JwksLoader has not been initialized. Call initSecurityEventCounter first.");
        }
        return loader;
    }
}
