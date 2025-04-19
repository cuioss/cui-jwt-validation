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
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.domain.claim.mapper.ClaimMapper;
import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.security.AlgorithmPreferences;
import lombok.Builder;
import lombok.NonNull;
import lombok.Singular;
import lombok.Value;

import java.util.Map;
import java.util.Set;

/**
 * Configuration class for issuer settings.
 * It aggregates all information needed to validate a JWT token.
 * <p>
 * This class contains the issuer URL, expected audience, expected client ID,
 * JwksLoader for loading keys and {@link AlgorithmPreferences}.
 * </p>
 */
@Builder
@Value
public class IssuerConfig {

    @NonNull
    String issuer;

    @Singular("expectedAudience")
    Set<String> expectedAudience;

    @Singular("expectedClientId")
    Set<String> expectedClientId;

    JwksLoader jwksLoader;

    @Builder.Default
    AlgorithmPreferences algorithmPreferences = new AlgorithmPreferences();

    /**
     * Custom claim mappers that take precedence over the default ones.
     * The key is the claim name, and the value is the mapper to use for that claim.
     */
    @Singular("claimMapper")
    Map<String, ClaimMapper> claimMappers;

}