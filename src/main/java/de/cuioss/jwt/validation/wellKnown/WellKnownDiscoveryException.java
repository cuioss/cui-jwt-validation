package de.cuioss.jwt.validation.wellKnown;

/**
 * Custom exception for errors encountered during the OpenID Connect
 * discovery process.
 */
public class WellKnownDiscoveryException extends RuntimeException {

    private static final long serialVersionUID = -813782058957368854L;

    /**
     * Constructs a new WellKnownDiscoveryException with the specified detail message.
     *
     * @param message the detail message.
     */
    public WellKnownDiscoveryException(String message) {
        super(message);
    }

    /**
     * Constructs a new WellKnownDiscoveryException with the specified detail message and
     * cause.
     *
     * @param message the detail message.
     * @param cause   the cause (which is saved for later retrieval by the
     *                {@link #getCause()} method). (A {@code null} value is
     *                permitted, and indicates that the cause is nonexistent or
     *                unknown.)
     */
    public WellKnownDiscoveryException(String message, Throwable cause) {
        super(message, cause);
    }
}
