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
package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonValue;

/**
 * Generator for invalid JWK keys.
 * <p>
 * This class implements the TypedGenerator for JsonObject and generates
 * JsonObject instances with invalid content for the keys "n", "e", "d", "x", or "y".
 * The content is either empty, null, or not Base64 compliant.
 * <p>
 * This class can be used in tests to generate invalid JWK keys.
 */
public class InvalidJWKKeyGenerator implements TypedGenerator<JsonObject> {

    private final TypedGenerator<String> keyGenerator = Generators.fixedValues("n", "e", "d", "x", "y");
    private final TypedGenerator<String> invalidContentGenerator = Generators.fixedValues("", null, "invalid_base64", "  ");

    @Override
    public JsonObject next() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        String key = keyGenerator.next();
        String invalidContent = invalidContentGenerator.next();
        if (invalidContent != null) {
            builder.add(key, invalidContent);
        } else {
            builder.add(key, JsonValue.NULL);
        }
        return builder.build();
    }

    @Override
    public Class<JsonObject> getType() {
        return JsonObject.class;
    }
}