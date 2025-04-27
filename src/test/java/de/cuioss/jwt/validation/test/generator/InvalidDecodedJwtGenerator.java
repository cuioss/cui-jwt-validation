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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.flow.DecodedJwt;
import de.cuioss.test.generator.TypedGenerator;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.util.Map;
import java.util.UUID;

/**
 * Generator for invalid DecodedJwt instances.
 * Can be configured with different {@link TokenType} values and provides
 * builder-like mutators to create various invalid validation scenarios.
 * 
 * This implementation uses InvalidTokenContentGenerator to create a TokenContent
 * and then transforms it to a DecodedJWT.
 */
public class InvalidDecodedJwtGenerator implements TypedGenerator<DecodedJwt> {

    private static final String DEFAULT_KEY_ID = "default-key-id";

    private final InvalidTokenContentGenerator tokenContentGenerator;

    // Additional flags not covered by InvalidTokenContentGenerator
    private boolean missingKeyId = false;
    private String customIssuer = null;

    /**
     * Constructor with validation type.
     *
     * @param tokenType the type of validation to generate
     */
    public InvalidDecodedJwtGenerator(TokenType tokenType) {
        this.tokenContentGenerator = new InvalidTokenContentGenerator(tokenType);
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public InvalidDecodedJwtGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    /**
     * Creates an invalid validation with missing issuer.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingIssuer() {
        tokenContentGenerator.withMissingIssuer();
        return this;
    }

    /**
     * Creates an invalid validation with missing subject.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingSubject() {
        tokenContentGenerator.withMissingSubject();
        return this;
    }

    /**
     * Creates an invalid validation with missing expiration.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingExpiration() {
        tokenContentGenerator.withMissingExpiration();
        return this;
    }

    /**
     * Creates an invalid validation that has already expired.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withExpiredToken() {
        tokenContentGenerator.withExpiredToken();
        return this;
    }

    /**
     * Creates an invalid validation with missing issuedAt.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingIssuedAt() {
        tokenContentGenerator.withMissingIssuedAt();
        return this;
    }

    /**
     * Creates an invalid validation with missing key ID.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingKeyId() {
        this.missingKeyId = true;
        return this;
    }

    /**
     * Creates an invalid validation with missing validation type.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingTokenType() {
        tokenContentGenerator.withMissingTokenType();
        return this;
    }

    /**
     * Creates an invalid validation with missing audience (important for ID tokens).
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withMissingAudience() {
        tokenContentGenerator.withMissingAudience();
        return this;
    }

    /**
     * Creates an invalid validation with a custom issuer.
     *
     * @param issuer the custom issuer to use
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator withCustomIssuer(String issuer) {
        this.customIssuer = issuer;
        return this;
    }

    /**
     * Resets all mutation flags to create a valid validation again.
     *
     * @return this generator for method chaining
     */
    public InvalidDecodedJwtGenerator reset() {
        tokenContentGenerator.reset();
        this.missingKeyId = false;
        this.customIssuer = null;
        return this;
    }

    /**
     * Converts a TokenContentImpl to a DecodedJwt.
     *
     * @param tokenContent the validation content to convert
     * @return a DecodedJwt instance
     */
    protected DecodedJwt tokenContentToDecodedJwt(TokenContentImpl tokenContent) {
        try {
            if (!missingKeyId && customIssuer == null) {
                // Use the toDecodedJwt method from TokenContentImpl if we don't need to customize the header or issuer
                return tokenContent.toDecodedJwt();
            } else {
                // When we need to customize the header or issuer
                // Create header with appropriate values
                JsonObjectBuilder headerBuilder = Json.createObjectBuilder()
                        .add("alg", "RS256")
                        .add("typ", "JWT");

                if (!missingKeyId) {
                    headerBuilder.add("kid", DEFAULT_KEY_ID);
                }

                // Build the header
                JsonObject header = headerBuilder.build();

                // Create body from validation content claims
                JsonObjectBuilder bodyBuilder = Json.createObjectBuilder();

                // Add all claims from the validation content
                for (Map.Entry<String, ClaimValue> entry : tokenContent.getClaims().entrySet()) {
                    String claimName = entry.getKey();
                    ClaimValue claimValue = entry.getValue();

                    // Handle different claim value types
                    switch (claimValue.getType()) {
                        case STRING_LIST:
                            // For list values, add as a JSON array
                            bodyBuilder.add(claimName, Json.createArrayBuilder(claimValue.getAsList()).build());
                            break;
                        case DATETIME:
                            // For date-time values, add as a number (epoch seconds)
                            bodyBuilder.add(claimName, Long.parseLong(claimValue.getOriginalString()));
                            break;
                        case STRING:
                        default:
                            // For string values, add as a string
                            if (claimName.equals("iss") && customIssuer != null) {
                                // Override issuer if custom issuer is set
                                bodyBuilder.add(claimName, customIssuer);
                            } else {
                                bodyBuilder.add(claimName, claimValue.getOriginalString());
                            }
                            break;
                    }
                }

                // Build the body
                JsonObject body = bodyBuilder.build();

                // Create a signature (not actually used for validation in tests)
                String signature = "test-signature";

                // Generate a unique identifier for this validation
                String uniqueId = UUID.randomUUID().toString();

                // Create validation parts with unique identifier
                String[] parts = new String[]{"header-part-" + uniqueId, "body-part-" + uniqueId, "signature-part-" + uniqueId};

                // Use the raw validation from the validation content if available, otherwise create one
                String rawToken = tokenContent.getRawToken();
                if (rawToken == null || rawToken.isEmpty()) {
                    rawToken = parts[0] + "." + parts[1] + "." + parts[2];
                }

                // Create and return the DecodedJwt
                return new DecodedJwt(header, body, signature, parts, rawToken);
            }
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert TokenContent to DecodedJwt", e);
        }
    }

    @Override
    public DecodedJwt next() {
        try {
            // Generate an invalid validation content using the InvalidTokenContentGenerator
            TokenContentImpl tokenContent = tokenContentGenerator.next();

            // Convert the validation content to a DecodedJwt
            return tokenContentToDecodedJwt(tokenContent);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate invalid DecodedJwt", e);
        }
    }
}
