package de.cuioss.jwt.quarkus;

import io.quarkus.test.junit.QuarkusTest;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Simple test to verify JUnit test discovery is working.
 */
@QuarkusTest
public class SimpleTest {

    @Test
    public void testSimple() {
        assertTrue(true, "Simple test should pass");
    }
}
