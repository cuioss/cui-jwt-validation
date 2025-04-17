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

import jakarta.json.Json;
import jakarta.json.JsonReaderFactory;
import lombok.Builder;
import lombok.Getter;
import lombok.Value;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration class for the TokenFactory.
 * <p>
 * This class provides configuration options for the TokenFactory, such as
 * maximum token size, maximum payload size, and logging behavior.
 * It also includes JSON parsing security settings like maximum string size,
 * maximum array size, and maximum depth.
 */
@Builder
@Value
public class TokenFactoryConfig {

    /**
     * Default maximum size of a JWT token in bytes to prevent overflow attacks.
     * 8KB as recommended by OAuth 2.0 JWT BCP Section 3.11.
     */
    public static final int DEFAULT_MAX_TOKEN_SIZE = 8 * 1024;

    /**
     * Default maximum size of decoded JSON payload in bytes.
     * 8KB as recommended by OAuth 2.0 JWT BCP Section 3.11.
     */
    public static final int DEFAULT_MAX_PAYLOAD_SIZE = 8 * 1024;

    /**
     * Default maximum string size for JSON parsing.
     */
    public static final int DEFAULT_MAX_STRING_SIZE = 4 * 1024;

    /**
     * Default maximum array size for JSON parsing.
     */
    public static final int DEFAULT_MAX_ARRAY_SIZE = 64;

    /**
     * Default maximum depth for JSON parsing.
     */
    public static final int DEFAULT_MAX_DEPTH = 10;

    /**
     * Maximum size of a JWT token in bytes to prevent overflow attacks.
     */
    @Builder.Default
    int maxTokenSize = DEFAULT_MAX_TOKEN_SIZE;

    /**
     * Maximum size of decoded JSON payload in bytes.
     */
    @Builder.Default
    int maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE;

    /**
     * Maximum string size for JSON parsing.
     */
    @Builder.Default
    int maxStringSize = DEFAULT_MAX_STRING_SIZE;

    /**
     * Maximum array size for JSON parsing.
     */
    @Builder.Default
    int maxArraySize = DEFAULT_MAX_ARRAY_SIZE;

    /**
     * Maximum depth for JSON parsing.
     */
    @Builder.Default
    int maxDepth = DEFAULT_MAX_DEPTH;

    /**
     * Flag to control whether warnings are logged when decoding fails.
     */
    @Builder.Default
    boolean logWarningsOnDecodeFailure = true;

    /**
     * Cached JsonReaderFactory with security settings.
     * This is lazily initialized to avoid unnecessary creation.
     */
    @Getter(lazy = true)
    private final JsonReaderFactory jsonReaderFactory = createJsonReaderFactory();

    /**
     * Creates a JsonReaderFactory with security settings.
     * This method is used by the lazy getter for jsonReaderFactory.
     *
     * @return a JsonReaderFactory configured with security settings
     */
    private JsonReaderFactory createJsonReaderFactory() {
        Map<String, Object> config = new HashMap<>();
        // Use the correct property names for Jakarta JSON API
        config.put("jakarta.json.stream.maxStringLength", maxStringSize);
        config.put("jakarta.json.stream.maxArraySize", maxArraySize);
        config.put("jakarta.json.stream.maxDepth", maxDepth);
        return Json.createReaderFactory(config);
    }
}
