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
 * Provides mappers for converting between JSON and typed claim values.
 * <p>
 * These mappers are used by the {@link de.cuioss.jwt.token.domain.claim.ClaimName} enum
 * to convert JSON claim values to strongly-typed {@link de.cuioss.jwt.token.domain.claim.ClaimValue} objects.
 * <p>
 * Key components:
 * <ul>
 *   <li>{@link de.cuioss.jwt.token.domain.claim.mapper.ClaimMapper} - Base interface for claim mappers</li>
 *   <li>{@link de.cuioss.jwt.token.domain.claim.mapper.IdentityMapper} - Maps string values directly</li>
 *   <li>{@link de.cuioss.jwt.token.domain.claim.mapper.JsonCollectionMapper} - Maps JSON arrays to collections</li>
 *   <li>{@link de.cuioss.jwt.token.domain.claim.mapper.OffsetDateTimeMapper} - Maps numeric timestamps to OffsetDateTime</li>
 *   <li>{@link de.cuioss.jwt.token.domain.claim.mapper.ScopeMapper} - Special mapper for the 'scope' claim</li>
 * </ul>
 * <p>
 * Each mapper is responsible for extracting a specific type of claim from a JSON object
 * and converting it to the appropriate Java type.
 * 
 * @since 1.0
 * @see de.cuioss.jwt.token.domain.claim.ClaimName
 * @see de.cuioss.jwt.token.domain.claim.ClaimValue
 */
package de.cuioss.jwt.token.domain.claim.mapper;