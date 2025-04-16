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
 * Provides classes for processing JWT tokens through a pipeline of operations.
 * <p>
 * This package implements the token processing flow, including parsing, validation, and building tokens.
 * The classes in this package work together to form a complete token processing pipeline.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.token.flow.NonValidatingJwtParser} - Parses JWT tokens without validating signatures</li>
 *   <li>{@link de.cuioss.jwt.token.flow.DecodedJwt} - Represents a decoded JWT token with header, body, and signature</li>
 *   <li>{@link de.cuioss.jwt.token.flow.TokenBuilder} - Creates typed token instances from decoded JWTs</li>
 *   <li>{@link de.cuioss.jwt.token.flow.TokenClaimValidator} - Validates token claims against issuer configuration</li>
 *   <li>{@link de.cuioss.jwt.token.flow.TokenHeaderValidator} - Validates token headers against issuer configuration</li>
 *   <li>{@link de.cuioss.jwt.token.flow.TokenSignatureValidator} - Validates token signatures using JWKS</li>
 *   <li>{@link de.cuioss.jwt.token.flow.IssuerConfig} - Configuration for a token issuer</li>
 *   <li>{@link de.cuioss.jwt.token.flow.TokenFactoryConfig} - Configuration for the token factory</li>
 * </ul>
 * <p>
 * The typical token processing flow is:
 * <ol>
 *   <li>Parse the token using {@link de.cuioss.jwt.token.flow.NonValidatingJwtParser}</li>
 *   <li>Validate the token header using {@link de.cuioss.jwt.token.flow.TokenHeaderValidator}</li>
 *   <li>Validate the token signature using {@link de.cuioss.jwt.token.flow.TokenSignatureValidator}</li>
 *   <li>Build a typed token using {@link de.cuioss.jwt.token.flow.TokenBuilder}</li>
 *   <li>Validate the token claims using {@link de.cuioss.jwt.token.flow.TokenClaimValidator}</li>
 * </ol>
 * <p>
 * This package implements security best practices for JWT token processing, including
 * token size validation, proper signature verification, and claim validation.
 * 
 * @since 1.0
 * @see de.cuioss.jwt.token.TokenFactory
 * @see de.cuioss.jwt.token.domain.token.TokenContent
 */
package de.cuioss.jwt.token.flow;