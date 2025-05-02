/*
 * Copyright 2025 the original author or authors.
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
package de.cuioss.jwt.validation.jwks.http;

import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Optional;

import static de.cuioss.jwt.validation.JWTValidationLogMessages.DEBUG;
import static de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;

/**
 * Handles HTTP operations for fetching JWKS content.
 * <p>
 * This class is responsible for:
 * <ul>
 *   <li>Creating and configuring the HTTP client</li>
 *   <li>Making requests to the JWKS endpoint</li>
 *   <li>Handling HTTP 304 "Not Modified" responses</li>
 *   <li>Managing ETag headers for conditional requests</li>
 * </ul>
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
public class JwksHttpClient {

    private static final CuiLogger LOGGER = new CuiLogger(JwksHttpClient.class);
    private static final int HTTP_OK = 200;
    private static final int HTTP_NOT_MODIFIED = 304;
    private static final String EMPTY_JWKS = "{}";

    @NonNull
    private final HttpJwksLoaderConfig config;

    @Getter
    private final HttpClient httpClient;

    /**
     * Response from a JWKS HTTP request.
     */
    public static class JwksHttpResponse {
        private final String content;
        private final String etag;
        private final boolean notModified;

        private JwksHttpResponse(String content, String etag, boolean notModified) {
            this.content = content;
            this.etag = etag;
            this.notModified = notModified;
        }

        /**
         * Creates a response for HTTP 304 Not Modified.
         *
         * @return a response indicating not modified
         */
        public static JwksHttpResponse notModified() {
            return new JwksHttpResponse(null, null, true);
        }

        /**
         * Creates a response with content and optional ETag.
         *
         * @param content the JWKS content
         * @param etag the ETag header value, may be null
         * @return a response with content
         */
        public static JwksHttpResponse withContent(String content, String etag) {
            return new JwksHttpResponse(content, etag, false);
        }

        /**
         * Creates an empty JWKS response.
         *
         * @return a response with empty JWKS content
         */
        public static JwksHttpResponse empty() {
            return new JwksHttpResponse(EMPTY_JWKS, null, false);
        }

        /**
         * Gets the JWKS content.
         *
         * @return the content, or null if not modified
         */
        public String getContent() {
            return content;
        }

        /**
         * Gets the ETag header value.
         *
         * @return the ETag, or null if not present
         */
        public Optional<String> getEtag() {
            return Optional.ofNullable(etag);
        }

        /**
         * Checks if the response indicates not modified (HTTP 304).
         *
         * @return true if not modified, false otherwise
         */
        public boolean isNotModified() {
            return notModified;
        }
    }

    /**
     * Creates a new JwksHttpClient with the specified configuration.
     *
     * @param config the configuration
     * @return a new JwksHttpClient
     */
    public static JwksHttpClient create(@NonNull HttpJwksLoaderConfig config) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(config.getRequestTimeoutSeconds()))
                .sslContext(config.getSslContext())
                .build();

        LOGGER.debug(DEBUG.USING_SSL_CONTEXT.format(config.getSslContext().getProtocol()));

        return new JwksHttpClient(config, httpClient);
    }

    /**
     * Fetches JWKS content from the configured endpoint.
     *
     * @param previousEtag the ETag from a previous response, may be null
     * @return the response containing JWKS content or not modified indication
     */
    public JwksHttpResponse fetchJwksContent(String previousEtag) {
        String uriString = config.getJwksUri().toString();
        LOGGER.debug(DEBUG.RESOLVING_KEY_LOADER.format(uriString));

        // Check if the URI is the dummy URI for invalid URLs
        if ("http://invalid-url".equals(uriString)) {
            LOGGER.warn(WARN.FAILED_TO_FETCH_JWKS.format(uriString));
            return JwksHttpResponse.empty();
        }

        // Build the request with conditional GET if we have an ETag
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder()
                .uri(config.getJwksUri())
                .timeout(Duration.ofSeconds(config.getRequestTimeoutSeconds()))
                .header("Accept", "application/json");

        if (previousEtag != null && !previousEtag.isEmpty()) {
            requestBuilder.header("If-None-Match", previousEtag);
        }

        HttpRequest request = requestBuilder.GET().build();

        try {
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            // Handle different response status codes
            if (response.statusCode() == HTTP_NOT_MODIFIED) {
                LOGGER.debug(DEBUG.RECEIVED_304_NOT_MODIFIED::format);
                return JwksHttpResponse.notModified();
            } else if (response.statusCode() != HTTP_OK) {
                LOGGER.warn(WARN.JWKS_FETCH_FAILED.format(response.statusCode()));
                return JwksHttpResponse.empty();
            }

            // Get content and ETag
            String jwksContent = response.body();
            String etag = response.headers().firstValue("ETag").orElse(null);

            LOGGER.debug(DEBUG.FETCHED_JWKS.format(config.getJwksUri().toString()));
            return JwksHttpResponse.withContent(jwksContent, etag);

        } catch (IOException | InterruptedException e) {
            LOGGER.warn(e, WARN.FAILED_TO_FETCH_JWKS.format(config.getJwksUri().toString()));
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            return JwksHttpResponse.empty();
        }
    }
}