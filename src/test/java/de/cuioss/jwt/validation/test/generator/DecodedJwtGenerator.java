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
package de.cuioss.jwt.validation.test.generator;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.flow.DecodedJwt;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for DecodedJwt instances.
 * Can be configured with different {@link TokenType} values to generate
 * appropriate validation content.
 * 
 * This implementation uses ValidTokenContentGenerator to create a TokenContent
 * and then transforms it to a DecodedJWT.
 */
public class DecodedJwtGenerator implements TypedGenerator<DecodedJwt> {

    private final ValidTokenContentGenerator tokenContentGenerator;

    /**
     * Constructor with validation type.
     *
     * @param tokenType the type of validation to generate
     */
    public DecodedJwtGenerator(TokenType tokenType) {
        this.tokenContentGenerator = new ValidTokenContentGenerator(tokenType);
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public DecodedJwtGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    /**
     * Converts a TokenContentImpl to a DecodedJwt.
     *
     * @param tokenContent the validation content to convert
     * @return a DecodedJwt instance
     */
    protected DecodedJwt tokenContentToDecodedJwt(TokenContentImpl tokenContent) {
        try {
            // Use the toDecodedJwt method from TokenContentImpl
            return tokenContent.toDecodedJwt();
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert TokenContent to DecodedJwt", e);
        }
    }

    @Override
    public DecodedJwt next() {
        try {
            // Generate a valid validation content using the ValidTokenContentGenerator
            TokenContentImpl tokenContent = tokenContentGenerator.next();

            // Convert the validation content to a DecodedJwt
            return tokenContentToDecodedJwt(tokenContent);
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate DecodedJwt", e);
        }
    }
}
