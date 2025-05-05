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

/**
 * Provides interfaces and implementations for JWT Token content.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.validation.domain.token.TokenContent} - Base interface for JWT Token content</li>
 *   <li>{@link de.cuioss.jwt.validation.domain.token.MinimalTokenContent} - Minimal interface for token content with raw token string and type</li>
 *   <li>{@link de.cuioss.jwt.validation.domain.token.BaseTokenContent} - Abstract base implementation of token content</li>
 *   <li>{@link de.cuioss.jwt.validation.domain.token.AccessTokenContent} - Specialized interface for OAuth2 access tokens</li>
 *   <li>{@link de.cuioss.jwt.validation.domain.token.IdTokenContent} - Specialized interface for OpenID Connect ID tokens</li>
 *   <li>{@link de.cuioss.jwt.validation.domain.token.RefreshTokenContent} - Specialized interface for OAuth2 refresh tokens</li>
 * </ul>
 * <p>
 * This package provides a type hierarchy for different validation types, with specialized interfaces
 * for each validation type defined in the OAuth2 and OpenID Connect specifications. The interfaces
 * provide convenient access to common claims and validation-specific functionality.
 * 
 * @since 1.0
 * @see de.cuioss.jwt.validation.domain.claim.ClaimName
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc6749">RFC 6749 - OAuth 2.0</a>
 * @see <a href="https://openid.net/specs/openid-connect-core-1_0.html">OpenID Connect Core 1.0</a>
 */
package de.cuioss.jwt.validation.domain.token;