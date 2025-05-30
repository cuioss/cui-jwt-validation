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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.test.generator.TypedGenerator;
import lombok.experimental.UtilityClass;

/**
 * Factory for creating TypedGenerator instances that produce TestTokenHolder objects.
 * <p>
 * This factory provides methods for creating generators for different token types:
 * <ul>
 *   <li>Access tokens</li>
 *   <li>ID tokens</li>
 *   <li>Refresh tokens</li>
 * </ul>
 * <p>
 * These generators are intended to replace the existing token generators in the project.
 */
@UtilityClass
public class TestTokenGenerators {

    /**
     * Creates a generator for TestTokenHolder objects with ACCESS_TOKEN type.
     *
     * @return a TypedGenerator that produces TestTokenHolder objects with ACCESS_TOKEN type
     */
    public static TypedGenerator<TestTokenHolder> accessTokens() {
        return () -> new TestTokenHolder(TokenType.ACCESS_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ACCESS_TOKEN));
    }

    /**
     * Creates a generator for TestTokenHolder objects with ID_TOKEN type.
     *
     * @return a TypedGenerator that produces TestTokenHolder objects with ID_TOKEN type
     */
    public static TypedGenerator<TestTokenHolder> idTokens() {
        return () -> new TestTokenHolder(TokenType.ID_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.ID_TOKEN));
    }

    /**
     * Creates a generator for TestTokenHolder objects with REFRESH_TOKEN type.
     *
     * @return a TypedGenerator that produces TestTokenHolder objects with REFRESH_TOKEN type
     */
    public static TypedGenerator<TestTokenHolder> refreshTokens() {
        return () -> new TestTokenHolder(TokenType.REFRESH_TOKEN, ClaimControlParameter.defaultForTokenType(TokenType.REFRESH_TOKEN));
    }
}
