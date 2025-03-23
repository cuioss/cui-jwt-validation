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
package de.cuioss.jwt.token.security;

import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.KeyMaterialHandler;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import jakarta.json.JsonReader;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.StringReader;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link JwkKeyHandler} with a focus on security aspects and potential attacks.
 */
class JwkKeyHandlerTest {

    // Helper method to create a JsonObject from a string
    private JsonObject createJsonObject(String jsonString) {
        try (JsonReader reader = Json.createReader(new StringReader(jsonString))) {
            return reader.readObject();
        }
    }

    // Helper method to create a single RSA JWK
    private JsonObject createRsaJwk() {
        RSAPublicKey publicKey = (RSAPublicKey) KeyMaterialHandler.getDefaultPublicKey();
        String jwkString = JWKSFactory.createSingleJwk(JWKSFactory.DEFAULT_KEY_ID);
        return createJsonObject(jwkString);
    }

    // Helper method to create a JsonObject with specific fields
    private JsonObject createJsonObject(String keyType, String n, String e, String kid) {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("kty", keyType);

        if (n != null) {
            builder.add("n", n);
        }

        if (e != null) {
            builder.add("e", e);
        }

        if (kid != null) {
            builder.add("kid", kid);
        }

        return builder.build();
    }

    // Helper method to create an EC JWK
    private JsonObject createEcJwk(String curve, String x, String y, String kid) {
        JsonObjectBuilder builder = Json.createObjectBuilder()
                .add("kty", "EC")
                .add("crv", curve);

        if (x != null) {
            builder.add("x", x);
        }

        if (y != null) {
            builder.add("y", y);
        }

        if (kid != null) {
            builder.add("kid", kid);
        }

        return builder.build();
    }

    @Test
    void shouldParseValidRsaKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Given a valid RSA JWK
        JsonObject jwk = createRsaJwk();

        // When parsing the key
        Key key = JwkKeyHandler.parseRsaKey(jwk);

        // Then the key should be parsed correctly
        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
    }

    @Test
    void shouldValidateRsaKeyFields() throws InvalidKeySpecException {
        // Given a valid RSA JWK
        JsonObject jwk = createRsaJwk();

        // When validating the key fields
        // Then no exception should be thrown
        assertDoesNotThrow(() -> JwkKeyHandler.validateRsaKeyFields(jwk));
    }

    @Test
    void shouldRejectRsaKeyWithMissingModulus() {
        // Given an RSA JWK with missing modulus
        JsonObject jwk = createJsonObject("RSA", null, "AQAB", "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateRsaKeyFields(jwk)
        );

        // And the exception message should indicate the missing field
        assertTrue(exception.getMessage().contains("missing required fields"));
    }

    @Test
    void shouldRejectRsaKeyWithMissingExponent() {
        // Given an RSA JWK with missing exponent
        JsonObject jwk = createJsonObject("RSA", "someModulus", null, "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateRsaKeyFields(jwk)
        );

        // And the exception message should indicate the missing field
        assertTrue(exception.getMessage().contains("missing required fields"));
    }

    @Test
    void shouldRejectRsaKeyWithInvalidBase64UrlModulus() {
        // Given an RSA JWK with invalid Base64 URL encoded modulus
        JsonObject jwk = createJsonObject("RSA", "invalid!base64", "AQAB", "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateRsaKeyFields(jwk)
        );

        // And the exception message should indicate the invalid value
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'n'"));
    }

    @Test
    void shouldRejectRsaKeyWithInvalidBase64UrlExponent() {
        // Given an RSA JWK with invalid Base64 URL encoded exponent
        JsonObject jwk = createJsonObject("RSA", "validModulus", "invalid!base64", "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateRsaKeyFields(jwk)
        );

        // And the exception message should indicate the invalid value
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'e'"));
    }

    @Test
    void shouldValidateEcKeyFields() throws InvalidKeySpecException {
        // Given a valid EC JWK
        JsonObject jwk = createEcJwk("P-256", "validXCoord", "validYCoord", "test-key");

        // When validating the key fields
        // Then no exception should be thrown
        assertDoesNotThrow(() -> JwkKeyHandler.validateEcKeyFields(jwk));
    }

    @Test
    void shouldRejectEcKeyWithMissingXCoordinate() {
        // Given an EC JWK with missing x coordinate
        JsonObject jwk = createEcJwk("P-256", null, "validYCoord", "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateEcKeyFields(jwk)
        );

        // And the exception message should indicate the missing field
        assertTrue(exception.getMessage().contains("missing required fields"));
    }

    @Test
    void shouldRejectEcKeyWithMissingYCoordinate() {
        // Given an EC JWK with missing y coordinate
        JsonObject jwk = createEcJwk("P-256", "validXCoord", null, "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateEcKeyFields(jwk)
        );

        // And the exception message should indicate the missing field
        assertTrue(exception.getMessage().contains("missing required fields"));
    }

    @Test
    void shouldRejectEcKeyWithInvalidBase64UrlXCoordinate() {
        // Given an EC JWK with invalid Base64 URL encoded x coordinate
        JsonObject jwk = createEcJwk("P-256", "invalid!base64", "validYCoord", "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateEcKeyFields(jwk)
        );

        // And the exception message should indicate the invalid value
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'x'"));
    }

    @Test
    void shouldRejectEcKeyWithInvalidBase64UrlYCoordinate() {
        // Given an EC JWK with invalid Base64 URL encoded y coordinate
        JsonObject jwk = createEcJwk("P-256", "validXCoord", "invalid!base64", "test-key");

        // When validating the key fields
        // Then an exception should be thrown
        InvalidKeySpecException exception = assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.validateEcKeyFields(jwk)
        );

        // And the exception message should indicate the invalid value
        assertTrue(exception.getMessage().contains("Invalid Base64 URL encoded value for 'y'"));
    }

    @Test
    void shouldThrowExceptionForUnsupportedEcCurve() {
        // Given a valid EC JWK
        JsonObject jwk = createEcJwk("P-256", "validXCoord", "validYCoord", "test-key");

        // When trying to parse the EC key
        // Then an exception should be thrown because EC curve support is not implemented
        assertThrows(
                InvalidKeySpecException.class,
                () -> JwkKeyHandler.parseEcKey(jwk)
        );
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "P-256", "P-384", "P-521"
    })
    void shouldDetermineCorrectEcAlgorithm(String curve) {
        // Given a curve name
        
        // When determining the EC algorithm
        String algorithm = JwkKeyHandler.determineEcAlgorithm(curve);

        // Then the correct algorithm should be returned
        switch (curve) {
            case "P-256":
                assertEquals("ES256", algorithm);
                break;
            case "P-384":
                assertEquals("ES384", algorithm);
                break;
            case "P-521":
                assertEquals("ES512", algorithm);
                break;
            default:
                fail("Unexpected curve: " + curve);
        }
    }

    @Test
    void shouldReturnDefaultAlgorithmForUnknownCurve() {
        // Given an unknown curve name
        String curve = "unknown-curve";

        // When determining the EC algorithm
        String algorithm = JwkKeyHandler.determineEcAlgorithm(curve);

        // Then the default algorithm should be returned
        assertEquals("ES256", algorithm);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "validBase64", "abc123", "ABC-_", "ABC-_="
    })
    void shouldValidateCorrectBase64UrlEncodedValues(String value) {
        // Given a valid Base64 URL encoded value
        
        // When validating the value
        boolean isValid = JwkKeyHandler.isValidBase64UrlEncoded(value);

        // Then it should be considered valid
        assertTrue(isValid);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "", "invalid!", "invalid#", "invalid$", "invalid%", "invalid&", "invalid+", "invalid/"
    })
    void shouldRejectInvalidBase64UrlEncodedValues(String value) {
        // Given an invalid Base64 URL encoded value
        
        // When validating the value
        boolean isValid = JwkKeyHandler.isValidBase64UrlEncoded(value);

        // Then it should be considered invalid
        assertFalse(isValid);
    }

    @Test
    void shouldHandleNullValuesInBase64Validation() {
        // Given a null value
        String value = null;

        // When validating the value
        boolean isValid = JwkKeyHandler.isValidBase64UrlEncoded(value);

        // Then it should be considered invalid
        assertFalse(isValid);
    }

    @Test
    void shouldHandleExtremelyLongBase64Values() {
        // Given an extremely long Base64 URL encoded value (potential DoS attack)
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 10000; i++) {
            sb.append("A");
        }
        String value = sb.toString();

        // When validating the value
        boolean isValid = JwkKeyHandler.isValidBase64UrlEncoded(value);

        // Then it should be considered valid (since it only contains valid characters)
        // This tests that the validation doesn't crash with very long inputs
        assertTrue(isValid);
    }
}