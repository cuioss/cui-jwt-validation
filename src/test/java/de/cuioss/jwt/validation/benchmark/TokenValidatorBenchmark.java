package de.cuioss.jwt.validation.benchmark;

import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.Benchmark;
import org.openjdk.jmh.annotations.BenchmarkMode;
import org.openjdk.jmh.annotations.Fork;
import org.openjdk.jmh.annotations.Measurement;
import org.openjdk.jmh.annotations.Mode;
import org.openjdk.jmh.annotations.OutputTimeUnit;
import org.openjdk.jmh.annotations.Scope;
import org.openjdk.jmh.annotations.Setup;
import org.openjdk.jmh.annotations.State;
import org.openjdk.jmh.annotations.Warmup;
import org.openjdk.jmh.infra.Blackhole;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.domain.token.IdTokenContent;
import de.cuioss.jwt.validation.domain.token.RefreshTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler; // Added
import io.jsonwebtoken.Jwts; // Added
import io.jsonwebtoken.SignatureAlgorithm; // Added

import java.security.PrivateKey; // Added
import java.util.Date; // Added
import java.util.Map; // Added

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class TokenValidatorBenchmark {

    private TokenValidator tokenValidator;
    private String accessToken;
    private String idToken;
    private String refreshToken;

    @Setup
    public void setup() {
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks(); // Uses RS256 and DEFAULT_KEY_ID
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("Benchmark-testIssuer")
                .expectedAudience("benchmark-client")
                .expectedClientId("benchmark-client")
                .jwksContent(jwksContent)
                .build();
        tokenValidator = new TokenValidator(issuerConfig);

        PrivateKey privateKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(InMemoryKeyMaterialHandler.Algorithm.RS256);
        String keyId = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;

        long currentTimeMillis = System.currentTimeMillis();
        long expTimeMillis = currentTimeMillis + 3600 * 1000; // 1 hour from now
        long iatSeconds = currentTimeMillis / 1000;
        long expSeconds = expTimeMillis / 1000;

        // Access Token
        accessToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .audience().add("benchmark-client").and()
                .subject("test-subject")
                .claim("client_id", "benchmark-client")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(expTimeMillis))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        // ID Token
        idToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .audience().add("benchmark-client").and()
                .subject("test-subject")
                .claim("client_id", "benchmark-client")
                .claim("nonce", "test-nonce")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(expTimeMillis))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();

        // Refresh Token - typically simpler, may only need iss, sub, exp
        refreshToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .subject("test-subject")
                .expiration(new Date(expTimeMillis))
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    @Benchmark
    public AccessTokenContent validateAccessToken() {
        try {
            return tokenValidator.createAccessToken(accessToken);
        } catch (TokenValidationException e) {
            // This should ideally not happen in a performance benchmark for valid tokens
            // If it does, the setup or token generation needs correction.
            // For now, rethrow to make it visible in benchmark results if it occurs.
            throw new RuntimeException("Access token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public IdTokenContent validateIdToken() {
        try {
            return tokenValidator.createIdToken(idToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("ID token validation failed in benchmark", e);
        }
    }

    @Benchmark
    public RefreshTokenContent validateRefreshToken() {
        // Refresh token validation is often lighter and might not throw exceptions
        // for certain "invalid" conditions if it's just parsing.
        // The createRefreshToken method in TokenValidator seems to try to parse claims
        // but ignore validation exceptions.
        return tokenValidator.createRefreshToken(refreshToken);
    }

    // Example of how to consume with Blackhole if methods don't return or to ensure computation
    @Benchmark
    public void validateAccessTokenAndConsume(Blackhole bh) {
        try {
            bh.consume(tokenValidator.createAccessToken(accessToken));
        } catch (TokenValidationException e) {
            bh.consume(e); // Consume exception if it's part of what's measured
        }
    }
}
