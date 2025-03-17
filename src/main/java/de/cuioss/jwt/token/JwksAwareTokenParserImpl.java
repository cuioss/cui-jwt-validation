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
package de.cuioss.jwt.token;

import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.jwt.token.adapter.JwtAdapter;
import de.cuioss.jwt.token.jwks.JwksClient;
import de.cuioss.tools.base.Preconditions;
import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.StringReader;
import java.security.Key;
import java.util.Base64;
import java.util.Optional;

import static de.cuioss.jwt.token.PortalTokenLogMessages.INFO;
import static de.cuioss.jwt.token.PortalTokenLogMessages.WARN;

/**
 * JWT parser implementation with support for remote JWKS (JSON Web Key Set) loading.
 * This parser extends the standard JJWT functionality by adding the ability
 * to fetch and manage public keys from a JWKS endpoint for token signature verification.
 * <p>
 * Key features:
 * <ul>
 *   <li>Remote JWKS endpoint configuration</li>
 *   <li>Automatic key refresh support</li>
 *   <li>TLS certificate configuration for secure key loading</li>
 *   <li>Issuer-based token validation</li>
 * </ul>
 * <p>
 * The parser can be configured using the builder pattern:
 * <pre>
 * JwksAwareTokenParserImpl parser = JwksAwareTokenParserImpl.builder()
 *     .jwksIssuer("https://auth.example.com")
 *     .jwksEndpoint("https://auth.example.com/.well-known/jwks.json")
 *     .jwksRefreshInterval(60)
 *     .build();
 * </pre>
 * <p>
 * This implementation is thread-safe and handles automatic key rotation
 * based on the configured refresh interval.
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_jwtparser}
 * <p>
 * Implements requirement: {@code CUI-JWT-1.3: Signature Validation}
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor
public class JwksAwareTokenParserImpl implements de.cuioss.jwt.token.JwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(JwksAwareTokenParserImpl.class);
    public static final int DEFAULT_REFRESH_INTERVAL = 180;

    private final JwtParser jwtParser;
    private final JwksClient jwksClient;

    @Getter
    private final String issuer;

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<Jws<Claims>> parseToken(String token) throws JwtException {
        LOGGER.debug("Parsing token");
        if (token == null || token.isBlank()) {
            LOGGER.warn(WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        try {
            // Extract the key ID from the token header
            // Split the token into parts
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                LOGGER.warn("Invalid JWT format: expected 3 parts but got %s", parts.length);
                return Optional.empty();
            }

            // Decode the header
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
            JsonObject header;
            try (JsonReader reader = Json.createReader(new StringReader(headerJson))) {
                header = reader.readObject();
            }

            // Get the key ID if present
            String kid = null;
            if (header.containsKey("kid")) {
                kid = header.getString("kid");
            }

            Optional<Key> key;
            if (kid != null) {
                // Get the key from the JWKS client using the key ID
                key = jwksClient.getKey(kid);
                if (key.isEmpty()) {
                    LOGGER.warn(WARN.KEY_NOT_FOUND.format(kid));
                    return Optional.empty();
                }
            } else {
                // If no key ID is present, try all available keys
                LOGGER.debug("No key ID found in token header, trying all available keys");
                key = jwksClient.getFirstKey();
                if (key.isEmpty()) {
                    LOGGER.warn("No keys available in JWKS");
                    return Optional.empty();
                }
            }

            // Create a new JwtParser with the signing key and parse the token
            LOGGER.debug("Using key with algorithm: %s", key.get().getAlgorithm());
            try {
                Jws<Claims> jws = Jwts.parserBuilder()
                        .setSigningKey(key.get())
                        .build()
                        .parseClaimsJws(token);

                // Verify the issuer
                String tokenIssuer = jws.getBody().getIssuer();
                if (!issuer.equals(tokenIssuer)) {
                    LOGGER.warn(WARN.ISSUER_MISMATCH.format(tokenIssuer, issuer));
                    return Optional.empty();
                }

                return Optional.of(jws);
            } catch (JwtException e) {
                LOGGER.warn(e, WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
                LOGGER.trace("Offending token '%s'", token);
                return Optional.empty();
            }
        } catch (JwtException e) {
            LOGGER.warn(e, WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            LOGGER.trace("Offending token '%s'", token);
            return Optional.empty();
        } catch (Exception e) {
            LOGGER.warn(e, "Error parsing token: %s", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<JsonWebToken> parse(String token) throws JwtException {
        LOGGER.debug("Parsing token to JsonWebToken");
        return parseToken(token).map(jws -> new JwtAdapter(jws, token));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supportsIssuer(String issuer) {
        return this.issuer.equals(issuer);
    }

    public static class Builder {
        private String jwksIssuer;
        private String jwksEndpoint;
        private Integer jwksRefreshInterval = DEFAULT_REFRESH_INTERVAL;
        private String tlsCertificatePath;

        /**
         * @param jwksIssuer must not be {@code null}. Represents the allowed issuer for token to be verified.
         * @return the {@link Builder} itself
         */
        public Builder jwksIssuer(@NonNull String jwksIssuer) {
            this.jwksIssuer = jwksIssuer;
            return this;
        }

        /**
         * @param jwksRefreshInterval If not set, it will be defaulted to {@link #DEFAULT_REFRESH_INTERVAL}
         * @return the {@link Builder} itself
         */
        public Builder jwksRefreshInterval(Integer jwksRefreshInterval) {
            this.jwksRefreshInterval = jwksRefreshInterval;
            return this;
        }

        /**
         * @param jwksEndpoint must not be {@code null}
         * @return the {@link Builder} itself
         */
        public Builder jwksEndpoint(@NonNull String jwksEndpoint) {
            this.jwksEndpoint = jwksEndpoint;
            return this;
        }

        /**
         * Sets the tlsCertificatePath for the ssl-connection
         *
         * @param tlsCertificatePath to be set
         * @return the {@link Builder} itself
         */
        public Builder tlsCertificatePath(String tlsCertificatePath) {
            this.tlsCertificatePath = tlsCertificatePath;
            return this;
        }

        /**
         * Build the {@link JwksAwareTokenParserImpl}
         * @return the configured {@link JwksAwareTokenParserImpl}
         */
        public JwksAwareTokenParserImpl build() {
            Preconditions.checkArgument(jwksIssuer != null, "jwksIssuer must be set");
            Preconditions.checkArgument(jwksEndpoint != null, "jwksEndpoint must be set");

            if (jwksRefreshInterval == null) {
                LOGGER.debug("Using default jwksRefreshInterval: %s", DEFAULT_REFRESH_INTERVAL);
                jwksRefreshInterval = DEFAULT_REFRESH_INTERVAL;
            }

            // Create the JWKS client
            JwksClient jwksClient = new JwksClient(jwksEndpoint, jwksRefreshInterval, tlsCertificatePath);

            // Create the JWT parser
            JwtParser jwtParser = Jwts.parserBuilder()
                    .setAllowedClockSkewSeconds(30)
                    .requireIssuer(jwksIssuer)
                    .build();

            LOGGER.info(INFO.CONFIGURED_JWKS.format(
                    jwksEndpoint,
                    jwksRefreshInterval,
                    jwksIssuer));

            return new JwksAwareTokenParserImpl(jwtParser, jwksClient, jwksIssuer);
        }
    }

    /**
     * Get a newly created builder
     */
    public static Builder builder() {
        return new Builder();
    }
}
