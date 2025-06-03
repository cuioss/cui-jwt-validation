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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Date;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class FailureScenarioBenchmark {

    private TokenValidator tokenValidator;

    private String validAccessToken;
    private String expiredToken;
    private String wrongIssuerToken;
    private String wrongAudienceToken;
    private String invalidSignatureToken;
    private String malformedToken;
    // private String missingKidToken; // Omitting for now, as precise setup is complex

    private PrivateKey signingKey;
    private String keyId;
    private PrivateKey wrongSigningKey;

    @Setup
    public void setup() throws NoSuchAlgorithmException {
        // 1. Setup Keys
        signingKey = InMemoryKeyMaterialHandler.getDefaultPrivateKey(InMemoryKeyMaterialHandler.Algorithm.RS256);
        keyId = InMemoryKeyMaterialHandler.DEFAULT_KEY_ID;

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair wrongKeyPair = keyPairGenerator.generateKeyPair();
        wrongSigningKey = wrongKeyPair.getPrivate();

        // 2. Configure TokenValidator
        String jwksContent = InMemoryJWKSFactory.createDefaultJwks(); // Uses the default key (signingKey's public part)
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("Benchmark-testIssuer")
                .expectedAudience("benchmark-client")
                .jwksContent(jwksContent)
                .build();
        tokenValidator = new TokenValidator(issuerConfig);

        // 3. Generate Tokens
        long currentTimeMillis = System.currentTimeMillis();
        long futureExpTimeMillis = currentTimeMillis + 3600 * 1000; // 1 hour from now
        long pastExpTimeMillis = currentTimeMillis - 3600 * 1000;   // 1 hour in the past

        // Valid Access Token
        validAccessToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .audience().add("benchmark-client").and()
                .subject("test-subject")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(futureExpTimeMillis))
                .signWith(signingKey, SignatureAlgorithm.RS256)
                .compact();

        // Expired Token
        expiredToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .audience().add("benchmark-client").and()
                .subject("test-subject")
                .issuedAt(new Date(currentTimeMillis - 7200 * 1000)) // Issued 2 hours ago
                .expiration(new Date(pastExpTimeMillis)) // Expired 1 hour ago
                .signWith(signingKey, SignatureAlgorithm.RS256)
                .compact();

        // Wrong Issuer Token
        wrongIssuerToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("rogue-issuer")
                .audience().add("benchmark-client").and()
                .subject("test-subject")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(futureExpTimeMillis))
                .signWith(signingKey, SignatureAlgorithm.RS256)
                .compact();

        // Wrong Audience Token
        wrongAudienceToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and()
                .issuer("Benchmark-testIssuer")
                .audience().add("rogue-audience").and()
                .subject("test-subject")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(futureExpTimeMillis))
                .signWith(signingKey, SignatureAlgorithm.RS256)
                .compact();

        // Invalid Signature Token
        invalidSignatureToken = Jwts.builder()
                .header().add(Map.of("kid", keyId)).and() // Can use same kid, key material is different
                .issuer("Benchmark-testIssuer")
                .audience().add("benchmark-client").and()
                .subject("test-subject")
                .issuedAt(new Date(currentTimeMillis))
                .expiration(new Date(futureExpTimeMillis))
                .signWith(wrongSigningKey, SignatureAlgorithm.RS256) // Signed with a different key
                .compact();

        // Malformed Token
        malformedToken = "this.is.not.a.valid.jwt";
    }

    @Benchmark
    public Object validateValidAccessToken() {
        try {
            return tokenValidator.createAccessToken(validAccessToken);
        } catch (TokenValidationException e) {
            return e; // Should not happen for this benchmark
        }
    }

    @Benchmark
    public Object validateExpiredToken() {
        try {
            return tokenValidator.createAccessToken(expiredToken);
        } catch (TokenValidationException e) {
            return e;
        }
    }

    @Benchmark
    public Object validateWrongIssuerToken() {
        try {
            return tokenValidator.createAccessToken(wrongIssuerToken);
        } catch (TokenValidationException e) {
            return e;
        }
    }

    @Benchmark
    public Object validateWrongAudienceToken() {
        try {
            return tokenValidator.createAccessToken(wrongAudienceToken);
        } catch (TokenValidationException e) {
            return e;
        }
    }

    @Benchmark
    public Object validateInvalidSignatureToken() {
        try {
            return tokenValidator.createAccessToken(invalidSignatureToken);
        } catch (TokenValidationException e) {
            return e;
        }
    }

    @Benchmark
    public Object validateMalformedToken() {
        try {
            return tokenValidator.createAccessToken(malformedToken);
        } catch (TokenValidationException e) {
            return e;
        }
    }
}
