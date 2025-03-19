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
package de.cuioss.jwt.token.test;

import de.cuioss.test.mockwebserver.dispatcher.HttpMethodMapper;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import de.cuioss.tools.io.FileLoaderUtility;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;
import mockwebserver3.MockResponse;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;

import java.util.Optional;
import java.util.Set;

import static jakarta.servlet.http.HttpServletResponse.SC_INTERNAL_SERVER_ERROR;
import static jakarta.servlet.http.HttpServletResponse.SC_OK;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Handles the Resolving of JWKS Files from the Mocked oauth-Server. In essence, it returns the file
 * "src/test/resources/token/test-public-key.jwks"
 */
public class JwksResolveDispatcher implements ModuleDispatcherElement {

    /**
     * "/oidc/jwks.json"
     */
    public static final String LOCAL_PATH = "/oidc/jwks.json";
    public static final String PUBLIC_KEY_JWKS = KeyMaterialHandler.PUBLIC_KEY_JWKS;
    public static final String PUBLIC_KEY_OTHER_JWKS = KeyMaterialHandler.BASE_PATH + "other-public-key.jwks";
    public static final String PUBLIC_KEY_OTHER = KeyMaterialHandler.PUBLIC_KEY_OTHER;

    public String currentKey;

    public JwksResolveDispatcher() {
        currentKey = PUBLIC_KEY_JWKS;
    }

    @Getter
    @Setter
    private int callCounter = 0;

    @Setter
    private boolean returnError = false;

    @Setter
    private boolean returnInvalidJson = false;

    @Setter
    private boolean returnEmptyJwks = false;

    @Setter
    private boolean returnMissingFieldsJwk = false;

    @Override
    public Optional<MockResponse> handleGet(@NonNull RecordedRequest request) {
        callCounter++;

        if (returnError) {
            return Optional.of(new MockResponse(SC_INTERNAL_SERVER_ERROR, Headers.of(), ""));
        }

        if (returnInvalidJson) {
            return Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    JWKSFactory.createInvalidJson()));
        }

        if (returnEmptyJwks) {
            return Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    JWKSFactory.createEmptyJwks()));
        }

        if (returnMissingFieldsJwk) {
            return Optional.of(new MockResponse(
                    SC_OK,
                    Headers.of("Content-Type", "application/json"),
                    JWKSFactory.createJwksWithMissingFields(JWKSFactory.TEST_KEY_ID)));
        }

        // Always generate a JWKS on the fly for the default key
        if (currentKey.equals(PUBLIC_KEY_JWKS)) {
            String jwks = generateJwksFromDynamicKey();
            return Optional.of(new MockResponse(SC_OK, Headers.of("Content-Type", "application/json"), jwks));
        } else {
            // For other keys, use the file
            return Optional.of(new MockResponse(SC_OK, Headers.of("Content-Type", "application/json"), FileLoaderUtility
                    .toStringUnchecked(FileLoaderUtility.getLoaderForPath(currentKey))));
        }
    }

    private String generateJwksFromDynamicKey() {
        // Get the public key from the key pair
        java.security.PublicKey publicKey = KeyMaterialHandler.getPublicKey();

        if (publicKey instanceof java.security.interfaces.RSAPublicKey) {
            java.security.interfaces.RSAPublicKey rsaKey = (java.security.interfaces.RSAPublicKey) publicKey;

            // Create JWKS JSON with the test key ID
            return JWKSFactory.createJwksFromRsaKey(rsaKey, JWKSFactory.TEST_KEY_ID);
        } else {
            throw new IllegalStateException("Only RSA keys are supported");
        }
    }

    public void switchToOtherPublicKey() {
        currentKey = PUBLIC_KEY_OTHER_JWKS;
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


}
