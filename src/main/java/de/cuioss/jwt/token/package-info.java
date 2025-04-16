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
 * in a Portal environment. This package focuses on token parsing, validation,
 * and management with support for multiple token issuers.
 * <p>
 * Key components:
 *
 * <p>
 * The package supports:
 * <ul>
 *   <li>Multi-issuer token validation</li>
 *   <li>JWKS (JSON Web Key Set) integration</li>
 *   <li>Role and scope-based authorization</li>
 *   <li>Token expiration management</li>
 * </ul>
 * <p>
 * Note: The implementation is primarily tested with Keycloak as the identity provider.
 * Some features may be specific to Keycloak's token implementation.
 */
package de.cuioss.jwt.token;
