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
package de.cuioss.jwt.token.jwks.key;

import de.cuioss.jwt.token.test.generator.InvalidJWKKeyGenerator;
import de.cuioss.jwt.token.test.generator.JwkKeyConstantsGenerator;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@EnableGeneratorController
class JwkKeyConstantsTest {

    private final JwkKeyConstantsGenerator validGenerator = new JwkKeyConstantsGenerator();
    private final InvalidJWKKeyGenerator invalidGenerator = new InvalidJWKKeyGenerator();

    @Nested
    class KeyTypeTests {

        @Test
        void shouldExtractKeyType() {
            JsonObject validJwk = validGenerator.next();
            Optional<String> keyType = JwkKeyConstants.KeyType.getString(validJwk);
            assertTrue(keyType.isPresent());
            assertFalse(keyType.get().isBlank());
        }

        @Test
        void shouldReturnEmptyForInvalidKeyType() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<String> keyType = JwkKeyConstants.KeyType.getString(invalidJwk);
            assertTrue(keyType.isEmpty());
        }
    }

    @Nested
    class ModulusTests {

        @Test
        void shouldExtractModulus() {
            JsonObject validJwk = validGenerator.next();
            Optional<BigInteger> modulus = JwkKeyConstants.Modulus.from(validJwk);
            assertTrue(modulus.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidModulus() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<BigInteger> modulus = JwkKeyConstants.Modulus.from(invalidJwk);
            assertTrue(modulus.isEmpty());
        }
    }

    @Nested
    class ExponentTests {

        @Test
        void shouldExtractExponent() {
            JsonObject validJwk = validGenerator.next();
            Optional<BigInteger> exponent = JwkKeyConstants.Exponent.from(validJwk);
            assertTrue(exponent.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidExponent() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<BigInteger> exponent = JwkKeyConstants.Exponent.from(invalidJwk);
            assertTrue(exponent.isEmpty());
        }
    }

    @Nested
    class KeysTests {

        @Test
        void shouldExtractKeys() {
            JsonObject validJwk = validGenerator.next();
            Optional<JsonArray> keys = JwkKeyConstants.Keys.extract(validJwk);
            assertTrue(keys.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidKeys() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<JsonArray> keys = JwkKeyConstants.Keys.extract(invalidJwk);
            assertTrue(keys.isEmpty());
        }
    }

    @Nested
    class AlgorithmTests {

        @Test
        void shouldExtractAlgorithm() {
            JsonObject validJwk = validGenerator.next();
            Optional<String> algorithm = JwkKeyConstants.Algorithm.from(validJwk);
            assertTrue(algorithm.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidAlgorithm() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<String> algorithm = JwkKeyConstants.Algorithm.from(invalidJwk);
            assertTrue(algorithm.isEmpty());
        }
    }

    @Nested
    class KeyIdTests {

        @Test
        void shouldExtractKeyId() {
            JsonObject validJwk = validGenerator.next();
            Optional<String> keyId = JwkKeyConstants.KeyId.from(validJwk);
            assertTrue(keyId.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidKeyId() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<String> keyId = JwkKeyConstants.KeyId.from(invalidJwk);
            assertTrue(keyId.isEmpty());
        }
    }

    @Nested
    class XCoordinateTests {

        @Test
        void shouldExtractXCoordinate() {
            JsonObject validJwk = validGenerator.next();
            Optional<BigInteger> xCoordinate = JwkKeyConstants.XCoordinate.from(validJwk);
            assertTrue(xCoordinate.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidXCoordinate() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<BigInteger> xCoordinate = JwkKeyConstants.XCoordinate.from(invalidJwk);
            assertTrue(xCoordinate.isEmpty());
        }
    }

    @Nested
    class YCoordinateTests {

        @Test
        void shouldExtractYCoordinate() {
            JsonObject validJwk = validGenerator.next();
            Optional<BigInteger> yCoordinate = JwkKeyConstants.YCoordinate.from(validJwk);
            assertTrue(yCoordinate.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidYCoordinate() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<BigInteger> yCoordinate = JwkKeyConstants.YCoordinate.from(invalidJwk);
            assertTrue(yCoordinate.isEmpty());
        }
    }

    @Nested
    class CurveTests {

        @Test
        void shouldExtractCurve() {
            JsonObject validJwk = validGenerator.next();
            Optional<String> curve = JwkKeyConstants.Curve.from(validJwk);
            assertTrue(curve.isPresent());
        }

        @Test
        void shouldReturnEmptyForInvalidCurve() {
            JsonObject invalidJwk = invalidGenerator.next();
            Optional<String> curve = JwkKeyConstants.Curve.from(invalidJwk);
            assertTrue(curve.isEmpty());
        }
    }
}