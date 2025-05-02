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
package de.cuioss.jwt.validation.domain.claim.mapper;

import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import jakarta.json.JsonObject;
import lombok.NonNull;

/***
 * A functional interface for mapping a claim from a {@link JsonObject} to a {@link ClaimValue}.
 * This is used to convert the JSON representation of a claim into its
 * corresponding Java object representation.
 *
 * @see ClaimValue
 */
@FunctionalInterface
public interface ClaimMapper {

    /**
     * Maps a claim from a {@link JsonObject} to a {@link ClaimValue}.
     *
     * @param jsonObject the JSON object containing the claim
     * @param claimName the name of the claim in the JSON object
     * @return the mapped claim as a ClaimValue
     */
    ClaimValue map(@NonNull JsonObject jsonObject, @NonNull String claimName);
}
