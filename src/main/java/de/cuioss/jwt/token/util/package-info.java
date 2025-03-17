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
 * Provides utility classes for token parsing and validation in multi-issuer environments.
 * These utilities support the core token handling functionality by providing specialized
 * parsers and validators.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.token.util.MultiIssuerJwtParser}:
 *     <ul>
 *       <li>Manages multiple token parsers for different issuers</li>
 *       <li>Provides dynamic parser selection based on token characteristics</li>
 *       <li>Supports thread-safe token parsing in multi-tenant environments</li>
 *     </ul>
 *   </li>
 *   <li>{@link de.cuioss.jwt.token.util.NonValidatingJwtParser}:
 *     <ul>
 *       <li>Performs preliminary token inspection without signature validation</li>
 *       <li>Implements security measures against token-based attacks</li>
 *       <li>Supports safe token content extraction for parser selection</li>
 *     </ul>
 *   </li>
 * </ul>
 * <p>
 * Security considerations:
 * <ul>
 *   <li>Token size validation to prevent memory exhaustion</li>
 *   <li>Safe Base64 decoding practices</li>
 *   <li>Clear separation between token inspection and validation</li>
 * </ul>
 * <p>
 * Note: These utilities are designed to work with the core token handling classes
 * in the parent package. They should not be used directly for token validation
 * in production code.
 *
 * @see de.cuioss.jwt.token
 */
package de.cuioss.jwt.token.util;
