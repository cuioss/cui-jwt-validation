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
package de.cuioss.jwt.validation.flow;

import de.cuioss.jwt.validation.TokenParserConfig;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.JsonReaderFactory;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link TokenParserConfig}.
 */
@EnableTestLogger
@DisplayName("Tests for TokenParserConfig")
class TokenParserConfigTest {

    @Test
    @DisplayName("Should create config with default values")
    void shouldCreateConfigWithDefaultValues() {
        // When
        TokenParserConfig config = TokenParserConfig.builder().build();

        // Then
        assertEquals(TokenParserConfig.DEFAULT_MAX_TOKEN_SIZE, config.getMaxTokenSize());
        assertEquals(TokenParserConfig.DEFAULT_MAX_PAYLOAD_SIZE, config.getMaxPayloadSize());
        assertEquals(TokenParserConfig.DEFAULT_MAX_STRING_SIZE, config.getMaxStringSize());
        assertEquals(TokenParserConfig.DEFAULT_MAX_ARRAY_SIZE, config.getMaxArraySize());
        assertEquals(TokenParserConfig.DEFAULT_MAX_DEPTH, config.getMaxDepth());
        assertTrue(config.isLogWarningsOnDecodeFailure());
    }

    @Test
    @DisplayName("Should create config with custom values")
    void shouldCreateConfigWithCustomValues() {
        // Given
        int customMaxTokenSize = 4096;
        int customMaxPayloadSize = 2048;
        int customMaxStringSize = 1024;
        int customMaxArraySize = 32;
        int customMaxDepth = 5;
        boolean customLogWarnings = false;

        // When
        TokenParserConfig config = TokenParserConfig.builder()
                .maxTokenSize(customMaxTokenSize)
                .maxPayloadSize(customMaxPayloadSize)
                .maxStringSize(customMaxStringSize)
                .maxArraySize(customMaxArraySize)
                .maxDepth(customMaxDepth)
                .logWarningsOnDecodeFailure(customLogWarnings)
                .build();

        // Then
        assertEquals(customMaxTokenSize, config.getMaxTokenSize());
        assertEquals(customMaxPayloadSize, config.getMaxPayloadSize());
        assertEquals(customMaxStringSize, config.getMaxStringSize());
        assertEquals(customMaxArraySize, config.getMaxArraySize());
        assertEquals(customMaxDepth, config.getMaxDepth());
        assertEquals(customLogWarnings, config.isLogWarningsOnDecodeFailure());
    }

    @Test
    @DisplayName("Should create JsonReaderFactory with security settings")
    void shouldCreateJsonReaderFactoryWithSecuritySettings() {
        // Given
        TokenParserConfig config = TokenParserConfig.builder().build();

        // When
        JsonReaderFactory factory = config.getJsonReaderFactory();

        // Then
        assertNotNull(factory, "JsonReaderFactory should not be null");
    }

    @Test
    @DisplayName("Should create JsonReaderFactory with custom security settings")
    void shouldCreateJsonReaderFactoryWithCustomSecuritySettings() {
        // Given
        int customMaxStringSize = 1024;
        int customMaxArraySize = 32;
        int customMaxDepth = 5;

        TokenParserConfig config = TokenParserConfig.builder()
                .maxStringSize(customMaxStringSize)
                .maxArraySize(customMaxArraySize)
                .maxDepth(customMaxDepth)
                .build();

        // When
        JsonReaderFactory factory = config.getJsonReaderFactory();

        // Then
        assertNotNull(factory, "JsonReaderFactory should not be null");
        // Note: We can't directly verify the configuration of the factory
        // as there's no public API to access its configuration
    }
}