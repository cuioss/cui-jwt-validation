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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;

/**
 * Parameter object for controlling which claims should be included or excluded
 * when generating token content. Used by {@link TokenContentImpl} to create
 * both valid and invalid tokens for testing purposes.
 */
public class ClaimControlParameter {
    private final String tokenPrefix;
    private final boolean missingIssuer;
    private final boolean missingSubject;
    private final boolean missingExpiration;
    private final boolean expiredToken;
    private final boolean missingIssuedAt;
    private final boolean missingTokenType;
    private final boolean missingScope;
    private final boolean missingAudience;
    private final boolean missingAuthorizedParty;

    private ClaimControlParameter(Builder builder) {
        this.tokenPrefix = builder.tokenPrefix;
        this.missingIssuer = builder.missingIssuer;
        this.missingSubject = builder.missingSubject;
        this.missingExpiration = builder.missingExpiration;
        this.expiredToken = builder.expiredToken;
        this.missingIssuedAt = builder.missingIssuedAt;
        this.missingTokenType = builder.missingTokenType;
        this.missingScope = builder.missingScope;
        this.missingAudience = builder.missingAudience;
        this.missingAuthorizedParty = builder.missingAuthorizedParty;
    }

    /**
     * @return the validation prefix
     */
    public String getTokenPrefix() {
        return tokenPrefix;
    }

    /**
     * @return whether the issuer claim should be missing
     */
    public boolean isMissingIssuer() {
        return missingIssuer;
    }

    /**
     * @return whether the subject claim should be missing
     */
    public boolean isMissingSubject() {
        return missingSubject;
    }

    /**
     * @return whether the expiration claim should be missing
     */
    public boolean isMissingExpiration() {
        return missingExpiration;
    }

    /**
     * @return whether the validation should be expired
     */
    public boolean isExpiredToken() {
        return expiredToken;
    }

    /**
     * @return whether the issued at claim should be missing
     */
    public boolean isMissingIssuedAt() {
        return missingIssuedAt;
    }

    /**
     * @return whether the validation type claim should be missing
     */
    public boolean isMissingTokenType() {
        return missingTokenType;
    }

    /**
     * @return whether the scope claim should be missing (only relevant for ACCESS_TOKEN)
     */
    public boolean isMissingScope() {
        return missingScope;
    }

    /**
     * @return whether the audience claim should be missing (only relevant for ID_TOKEN)
     */
    public boolean isMissingAudience() {
        return missingAudience;
    }

    /**
     * @return whether the authorized party claim should be missing
     */
    public boolean isMissingAuthorizedParty() {
        return missingAuthorizedParty;
    }

    /**
     * Creates a builder for ClaimControlParameter.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates default parameters for a valid validation of the given type.
     * This method sets appropriate defaults based on the validation type.
     *
     * @param tokenType the type of validation
     * @return a new ClaimControlParameter with default settings for valid tokens
     */
    public static ClaimControlParameter defaultForTokenType(TokenType tokenType) {
        if (tokenType == null) {
            throw new IllegalArgumentException("TokenType must not be null");
        }

        // All tokens have the same default settings for valid tokens
        return builder()
                .tokenPrefix("valid-validation-")
                .missingIssuer(false)
                .missingSubject(false)
                .missingExpiration(false)
                .expiredToken(false)
                .missingIssuedAt(false)
                .missingTokenType(false)
                .missingScope(false)
                .missingAudience(false)
                .build();
    }

    /**
     * Builder for ClaimControlParameter.
     */
    public static class Builder {
        private String tokenPrefix = "valid-validation-";
        private boolean missingIssuer = false;
        private boolean missingSubject = false;
        private boolean missingExpiration = false;
        private boolean expiredToken = false;
        private boolean missingIssuedAt = false;
        private boolean missingTokenType = false;
        private boolean missingScope = false;
        private boolean missingAudience = false;
        private boolean missingAuthorizedParty = false;

        private Builder() {
            // Private constructor to enforce the use of the static factory method
        }

        /**
         * Sets the validation prefix.
         *
         * @param tokenPrefix the prefix for the raw token string
         * @return this builder for method chaining
         */
        public Builder tokenPrefix(String tokenPrefix) {
            this.tokenPrefix = tokenPrefix;
            return this;
        }

        /**
         * Sets whether the issuer claim should be missing.
         *
         * @param missingIssuer true if the issuer claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingIssuer(boolean missingIssuer) {
            this.missingIssuer = missingIssuer;
            return this;
        }

        /**
         * Sets whether the subject claim should be missing.
         *
         * @param missingSubject true if the subject claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingSubject(boolean missingSubject) {
            this.missingSubject = missingSubject;
            return this;
        }

        /**
         * Sets whether the expiration claim should be missing.
         *
         * @param missingExpiration true if the expiration claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingExpiration(boolean missingExpiration) {
            this.missingExpiration = missingExpiration;
            return this;
        }

        /**
         * Sets whether the validation should be expired.
         *
         * @param expiredToken true if the validation should be expired
         * @return this builder for method chaining
         */
        public Builder expiredToken(boolean expiredToken) {
            this.expiredToken = expiredToken;
            return this;
        }

        /**
         * Sets whether the issued at claim should be missing.
         *
         * @param missingIssuedAt true if the issued at claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingIssuedAt(boolean missingIssuedAt) {
            this.missingIssuedAt = missingIssuedAt;
            return this;
        }

        /**
         * Sets whether the validation type claim should be missing.
         *
         * @param missingTokenType true if the validation type claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingTokenType(boolean missingTokenType) {
            this.missingTokenType = missingTokenType;
            return this;
        }

        /**
         * Sets whether the scope claim should be missing (only relevant for ACCESS_TOKEN).
         *
         * @param missingScope true if the scope claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingScope(boolean missingScope) {
            this.missingScope = missingScope;
            return this;
        }

        /**
         * Sets whether the audience claim should be missing (only relevant for ID_TOKEN).
         *
         * @param missingAudience true if the audience claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingAudience(boolean missingAudience) {
            this.missingAudience = missingAudience;
            return this;
        }

        /**
         * Sets whether the authorized party claim should be missing.
         *
         * @param missingAuthorizedParty true if the authorized party claim should be missing
         * @return this builder for method chaining
         */
        public Builder missingAuthorizedParty(boolean missingAuthorizedParty) {
            this.missingAuthorizedParty = missingAuthorizedParty;
            return this;
        }

        /**
         * Builds a new ClaimControlParameter with the current builder settings.
         *
         * @return a new ClaimControlParameter instance
         */
        public ClaimControlParameter build() {
            return new ClaimControlParameter(this);
        }
    }
}
