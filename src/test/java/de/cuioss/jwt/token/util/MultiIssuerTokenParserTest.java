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
package de.cuioss.jwt.token.util;

import de.cuioss.jwt.token.JwksAwareTokenParserImpl;
import de.cuioss.jwt.token.JwksAwareTokenParserImplTest;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import de.cuioss.jwt.token.test.TestTokenProducer;
import static de.cuioss.jwt.token.test.TestTokenProducer.*;
import static de.cuioss.test.juli.LogAsserts.assertLogMessagePresentContaining;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableTestLogger
@DisplayName("Tests MultiIssuerTokenParser functionality")
class MultiIssuerTokenParserTest {

    private static final CuiLogger LOGGER = new CuiLogger(MultiIssuerTokenParserTest.class);
    private static final String UNKNOWN_ISSUER = "unknown-issuer";
    private static final String INVALID_TOKEN = "invalid-token";

    private MultiIssuerJwtParser multiIssuerParser;
    private JwksAwareTokenParserImpl defaultParser;
    private JwksAwareTokenParserImpl otherParser;

    @BeforeEach
    void setUp() throws IOException {
        defaultParser = JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS();
        otherParser = JwksAwareTokenParserImplTest.getInvalidValidJWKSParserWithLocalJWKSAndWrongIssuer();

        multiIssuerParser = MultiIssuerJwtParser.builder()
                .addParser(defaultParser)
                .addParser(otherParser)
                .build();
        LOGGER.info("Initialized MultiIssuerJwtParser with default and other parser");
    }

    @Nested
    @DisplayName("Issuer Extraction Tests")
    @EnableTestLogger(debug = MultiIssuerJwtParser.class)
    class IssuerExtractionTests {

        @Test
        @DisplayName("Should extract issuer from valid token")
        void shouldExtractIssuerFromValidToken() {
            var token = validSignedJWTWithClaims(SOME_SCOPES);
            var extractedIssuer = multiIssuerParser.extractIssuer(token);

            assertTrue(extractedIssuer.isPresent(), "Issuer should be present for valid token");
            assertEquals(ISSUER, extractedIssuer.get(), "Extracted issuer should match expected");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Extracting issuer from token");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Extracted issuer: " + ISSUER);
        }

        @Test
        @DisplayName("Should handle invalid token for issuer extraction")
        void shouldHandleInvalidTokenForIssuerExtraction() {
            var extractedIssuer = multiIssuerParser.extractIssuer(INVALID_TOKEN);
            assertFalse(extractedIssuer.isPresent(), "Issuer should not be present for invalid token");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Extracting issuer from token");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Extracted issuer: <none>");
        }
    }

    @Nested
    @DisplayName("Parser Retrieval Tests")
    @EnableTestLogger(debug = MultiIssuerJwtParser.class)
    class ParserRetrievalTests {

        @Test
        @DisplayName("Should get parser for known issuer")
        void shouldGetParserForKnownIssuer() {
            var parser = multiIssuerParser.getParserForIssuer(ISSUER);

            assertTrue(parser.isPresent(), "Parser should be present for known issuer");
            assertEquals(defaultParser, parser.get(), "Retrieved parser should match default parser");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Looking up parser for issuer: " + ISSUER);
        }

        @Test
        @DisplayName("Should return empty for unknown issuer")
        void shouldReturnEmptyForUnknownIssuer() {
            var parser = multiIssuerParser.getParserForIssuer(UNKNOWN_ISSUER);
            assertFalse(parser.isPresent(), "Parser should not be present for unknown issuer");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Looking up parser for issuer: " + UNKNOWN_ISSUER);
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "No parser found for issuer: " + UNKNOWN_ISSUER);
        }

        @Test
        @DisplayName("Should get parser for valid token")
        void shouldGetParserForValidToken() {
            var token = validSignedJWTWithClaims(SOME_SCOPES);
            var parser = multiIssuerParser.getParserForToken(token);

            assertTrue(parser.isPresent(), "Parser should be present for valid token");
            assertEquals(defaultParser, parser.get(), "Retrieved parser should match default parser");
        }

        @Test
        @DisplayName("Should handle invalid token for parser retrieval")
        void shouldHandleInvalidTokenForParserRetrieval() {
            var parser = multiIssuerParser.getParserForToken(INVALID_TOKEN);
            assertFalse(parser.isPresent(), "Parser should not be present for invalid token");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Extracting issuer from token");
            assertLogMessagePresentContaining(TestLogLevel.DEBUG, "Extracted issuer: <none>");
        }
    }
}
