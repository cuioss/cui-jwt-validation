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
package de.cuioss.jwt.token.test.generator;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.flow.DecodedJwt;
import de.cuioss.test.generator.TypedGenerator;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Generator for invalid DecodedJwt instances.
 * Can be configured with different {@link TokenType} values and provides
 * builder-like mutators to create various invalid token scenarios.
 */
public class InvalidDecodedJwtGenerator implements TypedGenerator<DecodedJwt> {

    private static final String DEFAULT_KEY_ID = "default-key-id";
    private static final String DEFAULT_ISSUER = "test-issuer";
    private static final String DEFAULT_SUBJECT = "test-subject";
    private static final String DEFAULT_AUDIENCE = "test-audience";

    private final TokenType tokenType;

    // Mutation flags
    private boolean missingIssuer = false;
    private boolean missingSubject = false;
    private boolean missingExpiration = false;
    private boolean expiredToken = false;
    private boolean missingIssuedAt = false;
    private boolean missingKeyId = false;
    private boolean missingTokenType = false;
    private boolean missingAudience = false;
    private String customIssuer = null;

    /**
     * Constructor with token type.
     *
     * @param tokenType the type of token to generate
     */
    public InvalidDecodedJwtGenerator(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public InvalidDecodedJwtGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    /**
     * Creates an invalid token with missing issuer.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingIssuer() {
        this.missingIssuer = true;
        return this;
    }

    /**
     * Creates an invalid token with missing subject.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingSubject() {
        this.missingSubject = true;
        return this;
    }

    /**
     * Creates an invalid token with missing expiration.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingExpiration() {
        this.missingExpiration = true;
        return this;
    }

    /**
     * Creates an invalid token that has already expired.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withExpiredToken() {
        this.expiredToken = true;
        return this;
    }

    /**
     * Creates an invalid token with missing issuedAt.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingIssuedAt() {
        this.missingIssuedAt = true;
        return this;
    }

    /**
     * Creates an invalid token with missing key ID.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingKeyId() {
        this.missingKeyId = true;
        return this;
    }

    /**
     * Creates an invalid token with missing token type.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingTokenType() {
        this.missingTokenType = true;
        return this;
    }

    /**
     * Creates an invalid token with missing audience (important for ID tokens).
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingAudience() {
        this.missingAudience = true;
        return this;
    }

    /**
     * Creates an invalid token with a custom issuer.
     *
     * @param issuer the custom issuer to use
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withCustomIssuer(String issuer) {
        this.customIssuer = issuer;
        return this;
    }

    /**
     * Resets all mutation flags to create a valid token again.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator reset() {
        this.missingIssuer = false;
        this.missingSubject = false;
        this.missingExpiration = false;
        this.expiredToken = false;
        this.missingIssuedAt = false;
        this.missingKeyId = false;
        this.missingTokenType = false;
        this.missingAudience = false;
        this.customIssuer = null;
        return this;
    }

    @Override
    public DecodedJwt next() {
        try {
            // Create header with appropriate values
            JsonObjectBuilder headerBuilder = Json.createObjectBuilder()
                    .add("typ", "JWT");

            if (!missingKeyId) {
                headerBuilder.add("kid", DEFAULT_KEY_ID);
            }

            // Always add algorithm for now
            headerBuilder.add("alg", "RS256");

            // Create body with appropriate values based on token type
            JsonObjectBuilder bodyBuilder = Json.createObjectBuilder();

            // Add standard claims unless they should be missing
            if (!missingIssuer) {
                bodyBuilder.add("iss", customIssuer != null ? customIssuer : DEFAULT_ISSUER);
            }

            if (!missingSubject) {
                bodyBuilder.add("sub", DEFAULT_SUBJECT);
            }

            if (!missingIssuedAt) {
                bodyBuilder.add("iat", Date.from(Instant.now()).getTime() / 1000);
            }

            if (!missingExpiration) {
                if (expiredToken) {
                    // Set expiration to 1 hour in the past
                    bodyBuilder.add("exp", Date.from(Instant.now().minusSeconds(3600)).getTime() / 1000);
                } else {
                    // Set expiration to 1 hour in the future
                    bodyBuilder.add("exp", Date.from(Instant.now().plusSeconds(3600)).getTime() / 1000);
                }
            }

            bodyBuilder.add("jti", UUID.randomUUID().toString());

            // Add type-specific claims
            if (!missingTokenType) {
                switch (tokenType) {
                    case ACCESS_TOKEN:
                        bodyBuilder.add("typ", TokenType.ACCESS_TOKEN.getTypeClaimName())
                                .add("scope", "openid profile email");
                        break;
                    case ID_TOKEN:
                        bodyBuilder.add("typ", TokenType.ID_TOKEN.getTypeClaimName());
                        if (!missingAudience) {
                            bodyBuilder.add("aud", DEFAULT_AUDIENCE);
                        }
                        bodyBuilder.add("email", "test@example.com");
                        break;
                    case REFRESH_TOKEN:
                        bodyBuilder.add("typ", TokenType.REFRESH_TOKEN.getTypeClaimName());
                        break;
                    case UNKNOWN:
                    default:
                        bodyBuilder.add("typ", "unknown");
                        break;
                }
            }

            // Build the JSON objects
            JsonObject header = headerBuilder.build();
            JsonObject body = bodyBuilder.build();

            // Create a signature (not actually used for validation in tests)
            String signature = "test-signature";

            // Generate a unique identifier for this token
            String uniqueId = UUID.randomUUID().toString();

            // Create token parts with unique identifier
            String[] parts = new String[]{"header-part-" + uniqueId, "body-part-" + uniqueId, "signature-part-" + uniqueId};

            // Create raw token with unique identifier
            String rawToken = parts[0] + "." + parts[1] + "." + parts[2];

            // Create and return the DecodedJwt
            return new DecodedJwt(header, body, signature, parts, rawToken);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate invalid DecodedJwt", e);
        }
    }
}
