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
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for invalid TokenContentImpl instances.
 * Can be configured with different {@link TokenType} values and provides
 * builder-like mutators to create various invalid validation scenarios.
 * Uses the {@link TokenContentImpl} as a base but subtracts elements
 * that need to be removed.
 * 
 * This implementation delegates to {@link ClaimControlParameter.Builder} for
 * configuring which claims should be missing or invalid.
 */
public class InvalidTokenContentGenerator implements TypedGenerator<TokenContentImpl> {

    private final TokenType tokenType;
    private final ClaimControlParameter.Builder claimControlBuilder;

    /**
     * Constructor with validation type.
     *
     * @param tokenType the type of validation to generate
     */
    public InvalidTokenContentGenerator(TokenType tokenType) {
        this.tokenType = tokenType;
        this.claimControlBuilder = ClaimControlParameter.builder().tokenPrefix("invalid-validation-");
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public InvalidTokenContentGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    /**
     * Creates an invalid validation with missing issuer.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingIssuer() {
        claimControlBuilder.missingIssuer(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing subject.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingSubject() {
        claimControlBuilder.missingSubject(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing expiration.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingExpiration() {
        claimControlBuilder.missingExpiration(true);
        return this;
    }

    /**
     * Creates an invalid validation that has already expired.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withExpiredToken() {
        claimControlBuilder.expiredToken(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing issuedAt.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingIssuedAt() {
        claimControlBuilder.missingIssuedAt(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing validation type.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingTokenType() {
        claimControlBuilder.missingTokenType(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing scope (important for ACCESS tokens).
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingScope() {
        claimControlBuilder.missingScope(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing audience (important for ID tokens).
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingAudience() {
        claimControlBuilder.missingAudience(true);
        return this;
    }

    /**
     * Creates an invalid validation with missing authorized party.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingAuthorizedParty() {
        claimControlBuilder.missingAuthorizedParty(true);
        return this;
    }

    /**
     * Resets all mutation flags to create a valid validation again.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator reset() {
        // Create a new builder with default values
        this.claimControlBuilder
                .missingIssuer(false)
                .missingSubject(false)
                .missingExpiration(false)
                .expiredToken(false)
                .missingIssuedAt(false)
                .missingTokenType(false)
                .missingScope(false)
                .missingAudience(false)
                .missingAuthorizedParty(false);
        return this;
    }

    @Override
    public TokenContentImpl next() {
        // Build the ClaimControlParameter with the configured settings
        ClaimControlParameter claimControl = claimControlBuilder.build();

        // Create a new implementation of TokenContent with the claim control parameter
        return new TokenContentImpl(tokenType, claimControl);
    }
}
