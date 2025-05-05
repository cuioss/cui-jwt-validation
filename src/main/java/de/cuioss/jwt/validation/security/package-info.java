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
 * Provides security-related functionality for JWT validation handling.
 * <p>
 * This package contains classes that implement security best practices for JWT validation
 * processing, including algorithm preferences and secure SSL context provision.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.validation.security.AlgorithmPreferences} - Manages algorithm preferences for JWT validation signatures</li>
 *   <li>{@link de.cuioss.jwt.validation.security.SecureSSLContextProvider} - Provides secure SSL contexts for HTTPS connections</li>
 * </ul>
 * <p>
 * The classes in this package implement security best practices, including:
 * <ul>
 *   <li>Cryptographic agility - supporting multiple algorithms with preference ordering</li>
 *   <li>Secure defaults - using strong algorithms by default</li>
 *   <li>Explicit rejection of insecure algorithms</li>
 *   <li>Secure TLS configuration for HTTPS connections</li>
 * </ul>
 * <p>
 * These security features are used throughout the JWT validation handling framework to ensure
 * secure validation validation and JWKS retrieval.
 * 
 * @since 1.0
 * @see de.cuioss.jwt.validation.pipeline.TokenSignatureValidator
 * @see de.cuioss.jwt.validation.jwks.http.HttpJwksLoader
 */
package de.cuioss.jwt.validation.security;
