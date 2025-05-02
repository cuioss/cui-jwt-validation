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

import de.cuioss.test.generator.TypedGenerator;

import java.util.Set;

/**
 * Factory for unified access to validation generators.
 * Provides access to generators for various validation types and JWKS.
 * Includes variants for "default" or "alternative" mode.
 */
public class TokenGenerators {

    private TokenGenerators() {
        // Private constructor to prevent instantiation
    }

    /**
     * Gets a generator for access tokens in default mode.
     *
     * @return a generator for access tokens
     */
    public static TypedGenerator<String> accessTokens() {
        return new AccessTokenGenerator(false);
    }

    /**
     * Gets a generator for access tokens in alternative mode.
     *
     * @return a generator for access tokens
     */
    public static TypedGenerator<String> alternativeAccessTokens() {
        return new AccessTokenGenerator(true);
    }

    /**
     * Gets a generator for ID tokens in default mode.
     *
     * @return a generator for ID tokens
     */
    public static TypedGenerator<String> idTokens() {
        return new IDTokenGenerator(false);
    }

    /**
     * Gets a generator for ID tokens in alternative mode.
     *
     * @return a generator for ID tokens
     */
    public static TypedGenerator<String> alternativeIdTokens() {
        return new IDTokenGenerator(true);
    }

    /**
     * Gets a generator for refresh tokens in default mode.
     *
     * @return a generator for refresh tokens
     */
    public static TypedGenerator<String> refreshTokens() {
        return new RefreshTokenGenerator(false);
    }

    /**
     * Gets a generator for refresh tokens in alternative mode.
     *
     * @return a generator for refresh tokens
     */
    public static TypedGenerator<String> alternativeRefreshTokens() {
        return new RefreshTokenGenerator(true);
    }

    /**
     * Gets a generator for JWKS in default mode.
     *
     * @return a generator for JWKS
     */
    public static TypedGenerator<String> jwks() {
        return new JWKSGenerator(false);
    }

    /**
     * Gets a generator for JWKS in alternative mode.
     *
     * @return a generator for JWKS
     */
    public static TypedGenerator<String> alternativeJwks() {
        return new JWKSGenerator(true);
    }

    /**
     * Gets a generator for scopes.
     *
     * @return a generator for scopes
     */
    public static TypedGenerator<String> scopes() {
        return new ScopeGenerator();
    }

    /**
     * Gets a generator for roles.
     *
     * @return a generator for roles
     */
    public static TypedGenerator<Set<String>> roles() {
        return new RoleGenerator();
    }

    /**
     * Gets a generator for groups.
     *
     * @return a generator for groups
     */
    public static TypedGenerator<Set<String>> groups() {
        return new GroupGenerator();
    }
}