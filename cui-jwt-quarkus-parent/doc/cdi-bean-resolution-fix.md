# CDI Bean Resolution Fix for JwtValidationConfig

## Problem

The application was experiencing ambiguous dependency injection issues with the `JwtValidationConfig` interface. Multiple beans were implementing this interface without distinct qualifiers, causing CDI resolution failures.

## Root Cause

When multiple beans implement the same interface, CDI requires qualifiers to disambiguate between them. In our case:

1. The synthetic bean created by Quarkus's `@ConfigMapping` annotation implements `JwtValidationConfig`
2. The test implementation `TestJwtValidationConfig` also implements `JwtValidationConfig`
3. Both had the same default qualifier, causing ambiguity during injection

## Solution

The minimal solution involved:

1. Creating qualifier annotations:
   - `@DefaultConfig`: To mark the production configuration
   - `@TestConfig`: To mark the test configuration

2. Adding appropriate qualifiers to:
   - The implementation classes
   - Injection points

3. Creating a `TestConfigProducer` for test contexts that:
   - Provides both configurations with appropriate qualifiers
   - Uses an `@Alternative` bean that gets selected in test contexts via `application.properties`

## Implementation Details

1. Added two qualifier annotations:
   ```java
   @Qualifier
   @Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER})
   @Retention(RetentionPolicy.RUNTIME)
   @Documented
   public @interface DefaultConfig {}
   
   @Qualifier
   @Target({ElementType.TYPE, ElementType.METHOD, ElementType.FIELD, ElementType.PARAMETER})
   @Retention(RetentionPolicy.RUNTIME)
   @Documented
   public @interface TestConfig {}
   ```

2. Applied `@TestConfig` to the test implementation:
   ```java
   @ApplicationScoped
   @TestConfig
   public class TestJwtValidationConfig implements JwtValidationConfig {
       // implementation
   }
   ```

3. Added a producer for the default configuration that applies the qualifier:
   ```java
   @ApplicationScoped
   public class DefaultJwtValidationConfigProducer {
       @Produces
       @DefaultConfig
       @ApplicationScoped
       public JwtValidationConfig createDefaultConfig(JwtValidationConfig config) {
           return config;
       }
   }
   ```

4. Created a test producer that bridges between test and default configurations:
   ```java
   @ApplicationScoped
   @Alternative
   public class TestConfigProducer {
       @Inject
       @TestConfig
       JwtValidationConfig testConfig;
       
       @Produces
       @DefaultConfig
       @ApplicationScoped
       public JwtValidationConfig produceDefaultConfig() {
           return testConfig;
       }
   }
   ```

5. Updated injection points with the appropriate qualifier:
   ```java
   @Inject
   @DefaultConfig
   JwtValidationConfig jwtValidationConfig;
   ```

6. Configured the alternative bean in test resources via `application.properties`:
   ```properties
   quarkus.arc.selected-alternatives=de.cuioss.jwt.quarkus.config.TestConfigProducer
   ```

This minimal solution successfully resolved the CDI bean resolution issues without requiring changes to the core functionality or APIs.
