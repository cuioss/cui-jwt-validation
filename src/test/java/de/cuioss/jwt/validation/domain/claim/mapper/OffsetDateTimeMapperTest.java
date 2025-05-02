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
package de.cuioss.jwt.validation.domain.claim.mapper;

import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.claim.ClaimValueType;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests OffsetDateTimeMapper functionality")
class OffsetDateTimeMapperTest {

    private static final String CLAIM_NAME = "testDateTimeClaim";
    private final OffsetDateTimeMapper underTest = new OffsetDateTimeMapper();

    @Test
    @DisplayName("Should correctly map a valid numeric timestamp as number (JWT NumericDate)")
    void shouldMapValidNumericTimestampAsNumber() {
        // Given
        // 2023-01-15T12:30:45Z as epoch seconds
        long epochSeconds = 1673785845;
        OffsetDateTime expected = OffsetDateTime.ofInstant(
                Instant.ofEpochSecond(epochSeconds),
                ZoneId.systemDefault()
        );

        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, epochSeconds)
                .build();

        // When
        ClaimValue result = underTest.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertEquals(String.valueOf(epochSeconds), result.getOriginalString(), "Original string should be preserved");
        assertEquals(expected, result.getDateTime(), "DateTime should be correctly parsed");
        assertEquals(ClaimValueType.DATETIME, result.getType(), "Type should be DATETIME");
    }

    @Test
    @DisplayName("Should throw exception for numeric timestamp as string (not compliant with JWT spec)")
    void shouldThrowExceptionForNumericTimestampAsString() {
        // Given
        // 2023-01-15T12:30:45Z as epoch seconds
        long epochSeconds = 1673785845;
        String validTimestamp = String.valueOf(epochSeconds);

        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, validTimestamp);

        // Then
        assertThrows(IllegalArgumentException.class, () -> underTest.map(jsonObject, CLAIM_NAME),
                "Should throw IllegalArgumentException for string value (even if it's a valid numeric timestamp)");
    }

    @Test
    @DisplayName("Should throw exception for ISO-8601 date-time string (not compliant with JWT spec)")
    void shouldMapValidIsoDateTime() {
        // Given
        String validDateTime = "2023-01-15T12:30:45Z";

        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, validDateTime);

        // Then
        assertThrows(IllegalArgumentException.class, () -> underTest.map(jsonObject, CLAIM_NAME),
                "Should throw IllegalArgumentException for string value (even if it's a valid ISO-8601 date-time)");
    }

    @Test
    @DisplayName("Should handle null claim value")
    void shouldHandleNullClaimValue() {
        // Given
        JsonObject jsonObject = createJsonObjectWithNullClaim(CLAIM_NAME);

        // When
        ClaimValue result = underTest.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertNull(result.getOriginalString(), "Original string should be null");
        assertNull(result.getDateTime(), "DateTime should be null for null claim value");
        assertEquals(ClaimValueType.DATETIME, result.getType(), "Type should be DATETIME");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "\t", "\n"})
    @DisplayName("Should throw exception for blank string inputs (not compliant with JWT spec)")
    void shouldThrowExceptionForBlankStringInputs(String blankInput) {
        // Given
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, blankInput);

        // Then
        assertThrows(IllegalArgumentException.class, () -> underTest.map(jsonObject, CLAIM_NAME),
                "Should throw IllegalArgumentException for string value (even if it's blank)");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "not-a-date",
            "not-a-number",
            "123abc", // Not a valid number
            "2023-13-01T12:30:45Z", // Invalid month
            "2023-01-32T12:30:45Z", // Invalid day
            "2023-01-01T25:30:45Z", // Invalid hour
            "2023-01-01T12:60:45Z", // Invalid minute
            "2023-01-01T12:30:60Z", // Invalid second
            "2023-01-01T12:30:45" // Missing timezone
    })
    @DisplayName("Should throw exception for invalid date-time formats")
    void shouldThrowExceptionForInvalidFormats(String invalidDateTime) {
        // Given
        JsonObject jsonObject = createJsonObjectWithStringClaim(CLAIM_NAME, invalidDateTime);

        // Then
        assertThrows(IllegalArgumentException.class, () -> underTest.map(jsonObject, CLAIM_NAME),
                "Should throw IllegalArgumentException for invalid date-time format");
    }

    @Test
    @DisplayName("Should handle missing claim")
    void shouldHandleMissingClaim() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder().build();

        // When
        ClaimValue result = underTest.map(jsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertNull(result.getOriginalString(), "Original string should be null");
        assertNull(result.getDateTime(), "DateTime should be null for missing claim");
        assertEquals(ClaimValueType.DATETIME, result.getType(), "Type should be DATETIME");
    }

    @Test
    @DisplayName("Should handle empty JsonObject")
    void shouldHandleEmptyJsonObject() {
        // Given
        JsonObject emptyJsonObject = Json.createObjectBuilder().build();

        // When
        ClaimValue result = underTest.map(emptyJsonObject, CLAIM_NAME);

        // Then
        assertNotNull(result, "Result should not be null");
        assertNull(result.getOriginalString(), "Original string should be null");
        assertNull(result.getDateTime(), "DateTime should be null for empty JsonObject");
        assertEquals(ClaimValueType.DATETIME, result.getType(), "Type should be DATETIME");
    }

    @Test
    @DisplayName("Should throw exception for unsupported JSON value types")
    void shouldThrowExceptionForUnsupportedTypes() {
        // Given
        JsonObject jsonObject = Json.createObjectBuilder()
                .add(CLAIM_NAME, Json.createObjectBuilder().build()) // Object type is not supported
                .build();

        // Then
        assertThrows(IllegalArgumentException.class, () -> underTest.map(jsonObject, CLAIM_NAME),
                "Should throw IllegalArgumentException for unsupported JSON value type");
    }

    // Helper methods

    private JsonObject createJsonObjectWithStringClaim(String claimName, String value) {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        if (value != null) {
            builder.add(claimName, value);
        } else {
            builder.addNull(claimName);
        }
        return builder.build();
    }

    private JsonObject createJsonObjectWithNullClaim(String claimName) {
        return Json.createObjectBuilder()
                .addNull(claimName)
                .build();
    }
}
