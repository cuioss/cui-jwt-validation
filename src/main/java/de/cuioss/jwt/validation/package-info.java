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

/**
 * Provides a comprehensive framework for handling OAuth2 and OpenID Connect tokens
 * in a Portal environment. This package focuses on validation parsing, validation,
 * and management with support for multiple validation issuers.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.validation.TokenValidator} - Main entry point for creating and validating tokens</li>
 *   <li>{@link de.cuioss.jwt.validation.TokenType} - Enumeration of supported validation types</li>
 *   <li>{@link de.cuioss.jwt.validation.JWTValidationLogMessages} - Structured logging messages</li>
 * </ul>
 * <p>
 * The package supports:
 * <ul>
 *   <li>Multi-issuer validation validation</li>
 *   <li>JWKS (JSON Web Key Set) integration</li>
 *   <li>Role and scope-based authorization</li>
 *   <li>Token expiration management</li>
 * </ul>
 * <p>
 * Note: The implementation is primarily tested with Keycloak as the identity provider.
 * Some features may be specific to Keycloak's validation implementation.
 * 
 * @since 1.0
 */
package de.cuioss.jwt.validation;
