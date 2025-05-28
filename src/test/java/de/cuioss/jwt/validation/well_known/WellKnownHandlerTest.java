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
package de.cuioss.jwt.validation.well_known;

import de.cuioss.jwt.validation.test.dispatcher.WellKnownDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcher;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.Getter;
import org.junit.jupiter.api.*;

import java.net.MalformedURLException;
import java.net.URL;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link WellKnownHandler}.
 * <p>
 * Verifies the functionality of the WellKnownHandler class, which is responsible
 * for fetching and parsing the OpenID Connect discovery document from a
 * .well-known/openid-configuration endpoint.
 * </p>
 */
@EnableMockWebServer
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG, debug = WellKnownHandler.class)
@DisplayName("Tests WellKnownHandler functionality")
@ModuleDispatcher
class WellKnownHandlerTest {

    @Getter
    private static final WellKnownDispatcher wellKnownDispatcher = new WellKnownDispatcher();

    private URL baseUrl;

    @BeforeAll
    static void setUpBeforeAll() {
        // Set system property to use GET instead of HEAD for accessibility checks
        System.setProperty("de.cuioss.jwt.validation.useGetForAccessibilityCheck", "true");
    }

    /**
     * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
     * This method is called by the ModuleDispatcher framework.
     *
     * @return the WellKnownDispatcher
     */
    public ModuleDispatcherElement getModuleDispatcher() {
        return wellKnownDispatcher;
    }

    @BeforeEach
    void setUp(URIBuilder uriBuilder) throws MalformedURLException {
        // Get the base URL from the mock server
        baseUrl = new URL(uriBuilder.buildAsString());

        // Reset the dispatcher to its default state
        wellKnownDispatcher.returnDefault();

        // Reset the call counter
        wellKnownDispatcher.setCallCounter(0);
    }

    @Nested
    @DisplayName("Success Scenario Tests")
    @ModuleDispatcher
    class SuccessScenarioTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should successfully fetch and parse discovery document")
        void shouldFetchAndParseDiscoveryDocument(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .wellKnownUrl(wellKnownUrl)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify endpoints
            assertTrue(handler.getJwksUri().isPresent(), "JWKS URI should be present");
            assertEquals(baseUrl.toString() + "/oidc/jwks.json",
                    handler.getJwksUri().get().toString(),
                    "JWKS URI should match");

            assertTrue(handler.getIssuer().isPresent(), "Issuer should be present");
            assertEquals(baseUrl.toString(),
                    handler.getIssuer().get().toString(),
                    "Issuer should match");

            assertTrue(handler.getAuthorizationEndpoint().isPresent(), "Authorization endpoint should be present");
            assertEquals(baseUrl.toString() + "/protocol/openid-connect/auth",
                    handler.getAuthorizationEndpoint().get().toString(),
                    "Authorization endpoint should match");

            assertTrue(handler.getTokenEndpoint().isPresent(), "Token endpoint should be present");
            assertEquals(baseUrl.toString() + "/protocol/openid-connect/token",
                    handler.getTokenEndpoint().get().toString(),
                    "Token endpoint should match");

            assertTrue(handler.getUserinfoEndpoint().isPresent(), "Userinfo endpoint should be present");
            assertEquals(baseUrl.toString() + "/protocol/openid-connect/userinfo",
                    handler.getUserinfoEndpoint().get().toString(),
                    "Userinfo endpoint should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // No need to verify logging in this test
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    @ModuleDispatcher
    class ErrorHandlingTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should throw exception for null or empty URL")
        void shouldThrowExceptionForNullOrEmptyUrl() {
            // Test with null URL
            WellKnownDiscoveryException nullException = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl((String) null).build(),
                    "Should throw exception for null URL"
            );
            assertTrue(nullException.getMessage().contains("Well-known URL string must not be null or empty"),
                    "Exception message should mention that URL must not be null or empty");

            // Test with empty URL
            WellKnownDiscoveryException emptyException = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl("").build(),
                    "Should throw exception for empty URL"
            );
            assertTrue(emptyException.getMessage().contains("Well-known URL string must not be null or empty"),
                    "Exception message should mention that URL must not be null or empty");

            // Test with blank URL
            WellKnownDiscoveryException blankException = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl("   ").build(),
                    "Should throw exception for blank URL"
            );
            assertTrue(blankException.getMessage().contains("Well-known URL string must not be null or empty"),
                    "Exception message should mention that URL must not be null or empty");
        }

        @Test
        @DisplayName("Should throw exception for malformed URL")
        void shouldThrowExceptionForMalformedUrl() {
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl("not-a-url").build(),
                    "Should throw exception for malformed URL"
            );
            assertTrue(exception.getMessage().contains("Invalid .well-known URL"),
                    "Exception message should mention invalid URL");
        }

        @Test
        @DisplayName("Should throw exception when server returns error")
        void shouldThrowExceptionWhenServerReturnsError(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnError();
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When/Then
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build(),
                    "Should throw exception when server returns error"
            );
            // The actual error message might vary depending on the HTTP client
            // Just verify that an exception is thrown

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);
        }

        @Test
        @DisplayName("Should throw exception for invalid JSON response")
        void shouldThrowExceptionForInvalidJsonResponse(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnInvalidJson();
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When/Then
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build(),
                    "Should throw exception for invalid JSON response"
            );
            // The actual error message might vary depending on the JSON parser
            // Just verify that an exception is thrown

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);
        }

        @Test
        @DisplayName("Should throw exception when issuer is missing")
        void shouldThrowExceptionWhenIssuerIsMissing(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnMissingIssuer();
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When/Then
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build(),
                    "Should throw exception when issuer is missing"
            );
            assertTrue(exception.getMessage().contains("Required field 'issuer' not found"),
                    "Exception message should mention missing issuer field");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);
        }

        @Test
        @DisplayName("Should throw exception when jwks_uri is missing")
        void shouldThrowExceptionWhenJwksUriIsMissing(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnMissingJwksUri();
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When/Then
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build(),
                    "Should throw exception when jwks_uri is missing"
            );
            assertTrue(exception.getMessage().contains("Required URL field 'jwks_uri' is missing"),
                    "Exception message should mention missing jwks_uri field");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);
        }

        @Test
        @DisplayName("Should throw exception when issuer validation fails")
        void shouldThrowExceptionWhenIssuerValidationFails(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnInvalidIssuer();
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When/Then
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    () -> WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build(),
                    "Should throw exception when issuer validation fails"
            );
            assertTrue(exception.getMessage().contains("Issuer validation failed"),
                    "Exception message should mention issuer validation failure");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify logging
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    "Issuer validation failed");
        }
    }

    @Nested
    @DisplayName("Endpoint Retrieval Tests")
    @ModuleDispatcher
    class EndpointRetrievalTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should return empty Optional for missing optional endpoints")
        void shouldReturnEmptyOptionalForMissingOptionalEndpoints(URIBuilder uriBuilder) throws MalformedURLException {
            // Configure the dispatcher to return a document with only required fields
            wellKnownDispatcher.returnOnlyRequiredFields();

            // When
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());
            WellKnownHandler handler = WellKnownHandler.builder()
                    .wellKnownUrl(wellKnownUrl)
                    .build();

            // Then
            assertFalse(handler.getAuthorizationEndpoint().isPresent(), "Authorization endpoint should not be present");
            assertFalse(handler.getTokenEndpoint().isPresent(), "Token endpoint should not be present");
            assertFalse(handler.getUserinfoEndpoint().isPresent(), "Userinfo endpoint should not be present");

            // Required endpoints should still be present
            assertTrue(handler.getJwksUri().isPresent(), "JWKS URI should be present");
            assertTrue(handler.getIssuer().isPresent(), "Issuer should be present");
        }
    }

    @Nested
    @DisplayName("Logging Tests")
    @ModuleDispatcher
    class LoggingTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should log messages for successful operations")
        void shouldLogDebugMessagesForSuccessfulOperations(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When
            WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build();

            // Then
            // Verify that at least one log message is present
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    "Accessibility check for jwks_uri URL");
        }

        @Test
        @DisplayName("Should log error messages for failed operations")
        void shouldLogErrorMessagesForFailedOperations(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnInvalidIssuer();
            URL wellKnownUrl = new URL(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString());

            // When
            try {
                WellKnownHandler.builder().wellKnownUrl(wellKnownUrl).build();
                fail("Should have thrown WellKnownDiscoveryException");
            } catch (WellKnownDiscoveryException e) {
                // Expected exception
            }

            // Then
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    "Issuer validation failed");
        }
    }
}
