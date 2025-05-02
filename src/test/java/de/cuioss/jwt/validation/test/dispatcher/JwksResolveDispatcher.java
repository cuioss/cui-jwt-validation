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
package de.cuioss.jwt.validation.test.dispatcher;

import de.cuioss.jwt.validation.test.JWKSFactory;
import de.cuioss.jwt.validation.test.KeyMaterialHandler;
import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;
import java.util.Set;

import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Handles the Resolving of JWKS Files from64EncodedContent the Mocked oauth-Server. In essence, it returns the file
 * "src/test/resources/validation/test-public-key.jwks"
 */
@SuppressWarnings("UnusedReturnValue")
public class JwksResolveDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/jwks.json"
     */
    public static final String LOCAL_PATH = "/oidc/jwks.json";

    @Getter
    @Setter
    private int callCounter = 0;
    private ResponseStrategy responseStrategy = ResponseStrategy.DEFAULT;
    private boolean useAlternativeKey = false;

    public JwksResolveDispatcher() {
        // No initialization needed
    }

    /**
     * Convenience method to set the response strategy to return an error.
     *
     * @return this instance for method chaining
     */
    public JwksResolveDispatcher returnError() {
        this.responseStrategy = ResponseStrategy.ERROR;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return invalid JSON.
     *
     * @return this instance for method chaining
     */
    public JwksResolveDispatcher returnInvalidJson() {
        this.responseStrategy = ResponseStrategy.INVALID_JSON;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return an empty JWKS.
     *
     * @return this instance for method chaining
     */
    public JwksResolveDispatcher returnEmptyJwks() {
        this.responseStrategy = ResponseStrategy.EMPTY_JWKS;
        return this;
    }

    /**
     * Convenience method to set the response strategy to return a JWKS with missing fields.
     *
     * @return this instance for method chaining
     */
    public JwksResolveDispatcher returnMissingFieldsJwk() {
        this.responseStrategy = ResponseStrategy.MISSING_FIELDS_JWK;
        return this;
    }

    /**
     * Convenience method to reset the response strategy to the default.
     *
     * @return this instance for method chaining
     */
    public JwksResolveDispatcher returnDefault() {
        this.responseStrategy = ResponseStrategy.DEFAULT;
        return this;
    }

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        callCounter++;

        switch (responseStrategy) {
            case ERROR:
                return Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));

            case INVALID_JSON:
                return Optional.of(new MockResponse(
                        SC_OK,
                        Headers.of("Content-Type", "application/json"),
                        JWKSFactory.createInvalidJson()));

            case EMPTY_JWKS:
                return Optional.of(new MockResponse(
                        SC_OK,
                        Headers.of("Content-Type", "application/json"),
                        JWKSFactory.createEmptyJwks()));

            case MISSING_FIELDS_JWK:
                return Optional.of(new MockResponse(
                        SC_OK,
                        Headers.of("Content-Type", "application/json"),
                        JWKSFactory.createJwksWithMissingFields(JWKSFactory.DEFAULT_KEY_ID)));

            case DEFAULT:
            default:
                // Always generate a JWKS on the fly for the default key
                if (!useAlternativeKey) {
                    String jwks = generateJwksFromDynamicKey();
                    return Optional.of(new MockResponse(SC_OK, Headers.of("Content-Type", "application/json"), jwks));
                } else {
                    // For other keys, use the KeyMaterialHandler
                    return Optional.of(new MockResponse(SC_OK, Headers.of("Content-Type", "application/json"),
                            KeyMaterialHandler.getAlternativeJWKSContent()));
                }
        }
    }

    private String generateJwksFromDynamicKey() {
        // Get the public key from64EncodedContent the key pair
        PublicKey publicKey = KeyMaterialHandler.getDefaultPublicKey();

        if (publicKey instanceof RSAPublicKey rsaKey) {

            // Create JWKS JSON with the default key ID
            return JWKSFactory.createJwksFromRsaKey(rsaKey, JWKSFactory.DEFAULT_KEY_ID);
        } else {
            throw new IllegalStateException("Only RSA keys are supported");
        }
    }

    public void switchToOtherPublicKey() {
        useAlternativeKey = true;
    }

    @Override
    public String getBaseUrl() {
        return LOCAL_PATH;
    }

    @Override
    public @NonNull Set<HttpMethodMapper> supportedMethods() {
        return Set.of(HttpMethodMapper.GET);
    }

    /**
     * Verifies whether this endpoint was called the given times
     *
     * @param expected count of calls
     */
    public void assertCallsAnswered(int expected) {
        assertEquals(expected, callCounter);
    }

    /**
     * Enum representing the different response strategies for the JWKS resolver.
     */
    public enum ResponseStrategy {
        /**
         * Returns a normal JWKS response based on the current key.
         */
        DEFAULT,

        /**
         * Returns an HTTP 500 error response.
         */
        ERROR,

        /**
         * Returns invalid JSON content.
         */
        INVALID_JSON,

        /**
         * Returns an empty JWKS (valid JSON but no keys).
         */
        EMPTY_JWKS,

        /**
         * Returns a JWKS with missing required fields.
         */
        MISSING_FIELDS_JWK
    }


}
