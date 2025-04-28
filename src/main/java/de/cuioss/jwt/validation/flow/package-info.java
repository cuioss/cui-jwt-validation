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
 * This package implements the validation processing flow, including parsing, validation, and building tokens.
 * The classes in this package work together to form a complete validation processing pipeline.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.validation.flow.NonValidatingJwtParser} - Parses JWT tokens without validating signatures</li>
 *   <li>{@link de.cuioss.jwt.validation.flow.DecodedJwt} - Represents a decoded JWT validation with header, body, and signature</li>
 *   <li>{@link de.cuioss.jwt.validation.flow.TokenBuilder} - Creates typed validation instances from decoded JWTs</li>
 *   <li>{@link de.cuioss.jwt.validation.flow.TokenClaimValidator} - Validates validation claims against issuer configuration</li>
 *   <li>{@link de.cuioss.jwt.validation.flow.TokenHeaderValidator} - Validates validation headers against issuer configuration</li>
 *   <li>{@link de.cuioss.jwt.validation.flow.TokenSignatureValidator} - Validates validation signatures using JWKS</li>
 *   <li>{@link de.cuioss.jwt.validation.IssuerConfig} - Configuration for a validation issuer</li>
 *   <li>{@link de.cuioss.jwt.validation.ParserConfig} - Configuration for the validation factory</li>
 * </ul>
 * <p>
 * The typical validation processing flow is:
 * <ol>
 *   <li>Parse the validation using {@link de.cuioss.jwt.validation.flow.NonValidatingJwtParser}</li>
 *   <li>Validate the validation header using {@link de.cuioss.jwt.validation.flow.TokenHeaderValidator}</li>
 *   <li>Validate the validation signature using {@link de.cuioss.jwt.validation.flow.TokenSignatureValidator}</li>
 *   <li>Build a typed validation using {@link de.cuioss.jwt.validation.flow.TokenBuilder}</li>
 *   <li>Validate the validation claims using {@link de.cuioss.jwt.validation.flow.TokenClaimValidator}</li>
 * </ol>
 * <p>
 * This package implements security best practices for JWT validation processing, including
 * validation size validation, proper signature verification, and claim validation.
 * 
 * @since 1.0
 * @see de.cuioss.jwt.validation.TokenValidator
 * @see de.cuioss.jwt.validation.domain.token.TokenContent
 */
package de.cuioss.jwt.validation.flow;