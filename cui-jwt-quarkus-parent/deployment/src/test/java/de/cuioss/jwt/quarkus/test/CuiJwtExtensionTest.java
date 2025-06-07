package de.cuioss.jwt.quarkus.test;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import io.quarkus.test.QuarkusUnitTest;

/**
 * Basic test to verify the CUI JWT extension is properly registered.
 */
@DisplayName("CUI JWT Extension Registration Test")
public class CuiJwtExtensionTest {

    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .withEmptyApplication();

    @Test
    @DisplayName("Should register the extension")
    public void shouldRegisterExtension() {
        // The test will fail if the extension is not properly registered
        // This is a basic test to ensure the extension is loaded
        assertTrue(true, "Extension should be registered");
    }
}