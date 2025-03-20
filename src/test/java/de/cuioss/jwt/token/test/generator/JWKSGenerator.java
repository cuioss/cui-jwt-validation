package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.jwt.token.test.JWKSFactory;

/**
 * Generator for JWKS (JSON Web Key Sets).
 * Generates a JWKS JSON string.
 * Can be configured in "default" or "alternative" mode.
 */
public class JWKSGenerator implements TypedGenerator<String> {

    private final boolean useAlternativeMode;

    /**
     * Constructor with default mode (false = default mode, true = alternative mode).
     *
     * @param useAlternativeMode whether to use alternative mode
     */
    public JWKSGenerator(boolean useAlternativeMode) {
        this.useAlternativeMode = useAlternativeMode;
    }

    /**
     * Constructor with default mode (false).
     */
    public JWKSGenerator() {
        this(false);
    }

    @Override
    public String next() {
        if (useAlternativeMode) {
            return JWKSFactory.createValidJwksWithKeyId(JWKSFactory.ALTERNATIVE_KEY_ID);
        } else {
            return JWKSFactory.createDefaultJwks();
        }
    }
}