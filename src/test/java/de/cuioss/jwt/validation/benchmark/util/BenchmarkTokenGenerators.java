package de.cuioss.jwt.validation.benchmark.util;

import de.cuioss.jwt.validation.test.InMemoryKeyMaterialHandler;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.commons.lang3.RandomStringUtils;


public class BenchmarkTokenGenerators {

    public enum TokenSize {
        SMALL,   // Default, ~1KB or less
        MEDIUM,  // Add padding to ~5KB
        LARGE    // Add padding to ~10KB+
    }

    public enum TokenComplexity {
        SIMPLE,  // Basic set of claims
        COMPLEX  // Additional nested claims or more numerous claims
    }

    // Uses io.jsonwebtoken.SignatureAlgorithm directly for algorithm selection

    private static final InMemoryKeyMaterialHandler rsaKeyHandler = new InMemoryKeyMaterialHandler(); // For RS256, RS384, RS512

    // It's good practice to have separate keys for different algorithm families if needed
    // For now, focusing on RSA. EC keys would be generated differently:
    // private static final Key es256Key = Keys.keyPairFor(SignatureAlgorithm.ES256).getPrivate();
    // etc.

    public static String generateAccessToken(
            String issuer,
            String subject,
            String audience,
            long expirationMillis,
            TokenSize size,
            TokenComplexity complexity,
            SignatureAlgorithm algorithm) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", subject);
        claims.put("aud", audience);
        claims.put("exp", new Date(System.currentTimeMillis() + expirationMillis));
        claims.put("iat", new Date(System.currentTimeMillis()));
        claims.put("jti", UUID.randomUUID().toString());

        if (complexity == TokenComplexity.COMPLEX) {
            Map<String, Object> nestedClaim = new HashMap<>();
            nestedClaim.put("attr1", "value1");
            nestedClaim.put("attr2", true);
            nestedClaim.put("attr3", 12345);
            claims.put("complex_claim", nestedClaim);
            for (int i = 0; i < 5; i++) {
                claims.put("extra_claim_" + i, RandomStringUtils.randomAlphanumeric(50));
            }
        }

        // Adjust content for size
        // This is a simple way to increase size. More sophisticated padding might be needed.
        int paddingLength = 0;
        if (size == TokenSize.MEDIUM) {
            paddingLength = 4 * 1024; // Aim for roughly 5KB, actual size depends on encoding
        } else if (size == TokenSize.LARGE) {
            paddingLength = 9 * 1024; // Aim for roughly 10KB
        }
        if (paddingLength > 0) {
            claims.put("padding", RandomStringUtils.randomAlphanumeric(paddingLength));
        }

        Key signingKey;
        if (algorithm.getFamilyName().equals("RSA")) {
            // Map jjwt SignatureAlgorithm to InMemoryKeyMaterialHandler.Algorithm for RSA
            InMemoryKeyMaterialHandler.Algorithm rsaAlg;
            if (algorithm == SignatureAlgorithm.RS256) {
                rsaAlg = InMemoryKeyMaterialHandler.Algorithm.RS256;
            } else if (algorithm == SignatureAlgorithm.RS384) {
                rsaAlg = InMemoryKeyMaterialHandler.Algorithm.RS384;
            } else if (algorithm == SignatureAlgorithm.RS512) {
                rsaAlg = InMemoryKeyMaterialHandler.Algorithm.RS512;
            } else {
                throw new UnsupportedOperationException("Unsupported RSA SignatureAlgorithm: " + algorithm.getValue());
            }
            signingKey = rsaKeyHandler.getDefaultPrivateKey(rsaAlg);
        } else if (algorithm.getFamilyName().equals("Elliptic Curve")) {
            // This part needs actual EC key generation and storage.
            // Using a placeholder or throwing exception for now.
            // For a real implementation, generate and store appropriate EC keys.
            // Example: signingKey = Keys.keyPairFor(algorithm).getPrivate();
            // However, this generates a new key each time. For benchmarks, we need stable keys.
            // For now, we will restrict to RSA or throw.
            if (algorithm == SignatureAlgorithm.ES256) {
                 // Placeholder - this will fail if not prepared.
                 // Ideally, pre-generate and store an ES256 key pair.
                 // Let's assume rsaKeyHandler can provide this for now IF it were an EC handler
                 // For this initial step, we'll focus on RSA and make other algos a TODO
                 throw new UnsupportedOperationException("ES256 not yet supported with stable keys in this generator.");
            } else {
                throw new UnsupportedOperationException(algorithm.getValue() + " not yet supported with stable keys in this generator.");
            }
        } else {
            throw new UnsupportedOperationException("Algorithm family not supported: " + algorithm.getFamilyName());
        }


        return Jwts.builder()
                .setClaims(claims)
                .signWith(signingKey, algorithm)
                .compact();
    }
}
