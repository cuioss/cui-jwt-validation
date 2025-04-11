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
import de.cuioss.jwt.token.domain.token.TokenContent;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for invalid TokenContent instances.
 * Can be configured with different {@link TokenType} values and provides
 * builder-like mutators to create various invalid token scenarios.
 * Uses the {@link TokenContentImpl} as a base but subtracts elements
 * that need to be removed.
 */
public class InvalidTokenContentGenerator implements TypedGenerator<TokenContent> {

    private final TokenType tokenType;

    // Mutation flags
    private boolean missingIssuer = false;
    private boolean missingSubject = false;
    private boolean missingExpiration = false;
    private boolean expiredToken = false;
    private boolean missingIssuedAt = false;
    private boolean missingTokenType = false;
    private boolean missingScope = false;
    private boolean missingAudience = false;
    private boolean missingAuthorizedParty = false;

    /**
     * Constructor with token type.
     *
     * @param tokenType the type of token to generate
     */
    public InvalidTokenContentGenerator(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public InvalidTokenContentGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    /**
     * Creates an invalid token with missing issuer.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingIssuer() {
        this.missingIssuer = true;
        return this;
    }

    /**
     * Creates an invalid token with missing subject.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingSubject() {
        this.missingSubject = true;
        return this;
    }

    /**
     * Creates an invalid token with missing expiration.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingExpiration() {
        this.missingExpiration = true;
        return this;
    }

    /**
     * Creates an invalid token that has already expired.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withExpiredToken() {
        this.expiredToken = true;
        return this;
    }

    /**
     * Creates an invalid token with missing issuedAt.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingIssuedAt() {
        this.missingIssuedAt = true;
        return this;
    }

    /**
     * Creates an invalid token with missing token type.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingTokenType() {
        this.missingTokenType = true;
        return this;
    }

    /**
     * Creates an invalid token with missing scope (important for ACCESS tokens).
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingScope() {
        this.missingScope = true;
        return this;
    }

    /**
     * Creates an invalid token with missing audience (important for ID tokens).
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingAudience() {
        this.missingAudience = true;
        return this;
    }

    /**
     * Creates an invalid token with missing authorized party.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator withMissingAuthorizedParty() {
        this.missingAuthorizedParty = true;
        return this;
    }

    /**
     * Resets all mutation flags to create a valid token again.
     *
     * @return this generator for method chaining
     */
    public InvalidTokenContentGenerator reset() {
        this.missingIssuer = false;
        this.missingSubject = false;
        this.missingExpiration = false;
        this.expiredToken = false;
        this.missingIssuedAt = false;
        this.missingTokenType = false;
        this.missingScope = false;
        this.missingAudience = false;
        this.missingAuthorizedParty = false;
        return this;
    }

    @Override
    public TokenContent next() {
        // Create a ClaimControlParameter with the specified mutations
        ClaimControlParameter claimControl = ClaimControlParameter.builder()
                .tokenPrefix("invalid-token-")
                .missingIssuer(missingIssuer)
                .missingSubject(missingSubject)
                .missingExpiration(missingExpiration)
                .expiredToken(expiredToken)
                .missingIssuedAt(missingIssuedAt)
                .missingTokenType(missingTokenType)
                .missingScope(missingScope)
                .missingAudience(missingAudience)
                .missingAuthorizedParty(missingAuthorizedParty)
                .build();

        // Create a new implementation of TokenContent with the claim control parameter
        return new TokenContentImpl(tokenType, claimControl);
    }
}
