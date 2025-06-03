package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Benchmark that measures system performance under high rates of validation errors.
 * This benchmark simulates scenarios with varying percentages of invalid tokens
 * and measures the impact on overall system throughput.
 */
@State(Scope.Benchmark)
@BenchmarkMode({Mode.Throughput, Mode.AverageTime})
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class ErrorLoadBenchmark {

    private TokenValidator tokenValidator;
    private List<String> validTokens;
    private List<String> invalidTokens;

    @Param({"0", "10", "50", "90", "100"})
    private int errorPercentage;

    // Number of tokens to generate for each category
    private static final int TOKEN_COUNT = 100;

    @Setup
    public void setup() throws NoSuchAlgorithmException {
        // 1. Setup Keys
        PrivateKey signingKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(InMemoryKeyMaterialHandler.Algorithm.RS256);
        String keyId = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair wrongKeyPair = keyPairGenerator.generateKeyPair();
        PrivateKey wrongSigningKey = wrongKeyPair.getPrivate();

        // 2. Configure TokenValidator
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks(); // Uses the default key (signingKey's public part)
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("Benchmark-testIssuer")
                .expectedAudience("benchmark-client")
                .jwksContent(jwksContent)
                .build();
        tokenValidator = new TokenValidator(issuerConfig);

        // 3. Generate Token Lists
        validTokens = new ArrayList<>(TOKEN_COUNT);
        invalidTokens = new ArrayList<>(TOKEN_COUNT);

        long currentTimeMillis = System.currentTimeMillis();
        long futureExpTimeMillis = currentTimeMillis + 3600 * 1000; // 1 hour from now
        long pastExpTimeMillis = currentTimeMillis - 3600 * 1000;   // 1 hour in the past

        // Generate valid tokens
        for (int i = 0; i < TOKEN_COUNT; i++) {
            String validToken = Jwts.builder()
                    .header().add(Map.of("kid", keyId)).and()
                    .issuer("Benchmark-testIssuer")
                    .audience().add("benchmark-client").and()
                    .subject("test-subject-" + i)
                    .issuedAt(new Date(currentTimeMillis))
                    .expiration(new Date(futureExpTimeMillis))
                    .signWith(signingKey)
                    .compact();
            validTokens.add(validToken);
        }

        // Generate different types of invalid tokens
        for (int i = 0; i < TOKEN_COUNT; i++) {
            // Distribute invalid tokens across different error types
            int errorType = i % 5;
            String invalidToken;

            switch (errorType) {
                case 0: // Expired token
                    invalidToken = Jwts.builder()
                            .header().add(Map.of("kid", keyId)).and()
                            .issuer("Benchmark-testIssuer")
                            .audience().add("benchmark-client").and()
                            .subject("test-subject-" + i)
                            .issuedAt(new Date(currentTimeMillis - 7200 * 1000))
                            .expiration(new Date(pastExpTimeMillis))
                            .signWith(signingKey)
                            .compact();
                    break;
                case 1: // Wrong issuer
                    invalidToken = Jwts.builder()
                            .header().add(Map.of("kid", keyId)).and()
                            .issuer("rogue-issuer-" + i)
                            .audience().add("benchmark-client").and()
                            .subject("test-subject-" + i)
                            .issuedAt(new Date(currentTimeMillis))
                            .expiration(new Date(futureExpTimeMillis))
                            .signWith(signingKey)
                            .compact();
                    break;
                case 2: // Wrong audience
                    invalidToken = Jwts.builder()
                            .header().add(Map.of("kid", keyId)).and()
                            .issuer("Benchmark-testIssuer")
                            .audience().add("rogue-audience-" + i).and()
                            .subject("test-subject-" + i)
                            .issuedAt(new Date(currentTimeMillis))
                            .expiration(new Date(futureExpTimeMillis))
                            .signWith(signingKey)
                            .compact();
                    break;
                case 3: // Invalid signature
                    invalidToken = Jwts.builder()
                            .header().add(Map.of("kid", keyId)).and()
                            .issuer("Benchmark-testIssuer")
                            .audience().add("benchmark-client").and()
                            .subject("test-subject-" + i)
                            .issuedAt(new Date(currentTimeMillis))
                            .expiration(new Date(futureExpTimeMillis))
                            .signWith(wrongSigningKey)
                            .compact();
                    break;
                case 4: // Malformed token
                default:
                    invalidToken = "this.is.not.a.valid.jwt-" + i;
                    break;
            }

            invalidTokens.add(invalidToken);
        }
    }

    /**
     * Selects a token based on the configured error percentage.
     * 
     * @return A token string that has the probability of being invalid
     * according to the errorPercentage parameter
     */
    private String selectToken() {
        // If errorPercentage is 0, always return valid token
        if (errorPercentage == 0) {
            int index = ThreadLocalRandom.current().nextInt(validTokens.size());
            return validTokens.get(index);
        }

        // If errorPercentage is 100, always return invalid token
        if (errorPercentage == 100) {
            int index = ThreadLocalRandom.current().nextInt(invalidTokens.size());
            return invalidTokens.get(index);
        }

        // Otherwise, select based on probability
        int randomValue = ThreadLocalRandom.current().nextInt(100);
        if (randomValue < errorPercentage) {
            // Return an invalid token
            int index = ThreadLocalRandom.current().nextInt(invalidTokens.size());
            return invalidTokens.get(index);
        } else {
            // Return a valid token
            int index = ThreadLocalRandom.current().nextInt(validTokens.size());
            return validTokens.get(index);
        }
    }

    @Benchmark
    public Object validateMixedTokens(Blackhole blackhole) {
        // Select token based on current iteration and errorPercentage
        String token = selectToken();
        try {
            AccessTokenContent result = tokenValidator.createAccessToken(token);
            blackhole.consume(result);
            return result;
        } catch (TokenValidationException e) {
            blackhole.consume(e);
            return e;
        }
    }
}
