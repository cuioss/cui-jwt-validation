/*
 * Copyright 2023 the original author or authors.
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
package de.cuioss.jwt.token.jwks;

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.tools.logging.CuiLogger;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import javax.net.ssl.SSLContext;
import java.nio.file.Path;

/**
 * Factory for creating instances of {@link JwksLoader}.
 * <p>
 * Key features:
 * <ul>
 *   <li>Creates appropriate loader based on the JWKS URL</li>
 *   <li>Supports HTTP and file-based JWKS sources</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * JwksLoader loader = JwksLoaderFactory.createHttpLoader("https://auth.example.com/.well-known/jwks.json", 60, null);
 * Optional&lt;Key&gt; key = loader.getKey("kid123");
 * </pre>
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_jwksclient}
 * <p>
 * Implements requirement: {@code CUI-JWT-4.1: JWKS Endpoint Support}
 *
 * @author Oliver Wolff
 */
@UtilityClass
public class JwksLoaderFactory {

    private static final CuiLogger LOGGER = new CuiLogger(JwksLoaderFactory.class);


    /**
     * Creates a JwksLoader that loads JWKS from an HTTP endpoint.
     *
     * @param jwksUrl the URL of the JWKS endpoint
     * @param refreshIntervalSeconds the interval in seconds at which to refresh the keys
     * @param sslContext optional SSLContext for secure connections, if null the default SSLContext from VM configuration is used
     * @return an instance of JwksLoader
     */
    public static JwksLoader createHttpLoader(@NonNull String jwksUrl, int refreshIntervalSeconds, SSLContext sslContext) {
        return new HttpJwksLoader(jwksUrl, refreshIntervalSeconds, sslContext);
    }

    /**
     * Creates a JwksLoader that loads JWKS from a file.
     *
     * @param filePath the path to the JWKS file
     * @return an instance of JwksLoader
     */
    public static JwksLoader createFileLoader(@NonNull String filePath) {
        LOGGER.debug("Resolving key loader for JWKS file: %s", filePath);
        try {
            String jwksContent = new String(java.nio.file.Files.readAllBytes(Path.of(filePath)));
            LOGGER.debug("Successfully read JWKS from file: %s", filePath);
            JWKSKeyLoader keyLoader = new JWKSKeyLoader(jwksContent);
            LOGGER.debug("Successfully loaded %s keys", keyLoader.keySet().size());
            return keyLoader;
        } catch (java.io.IOException e) {
            LOGGER.warn(e, JWTTokenLogMessages.WARN.FAILED_TO_READ_JWKS_FILE.format(filePath));
            return new JWKSKeyLoader("{}"); // Empty JWKS
        }
    }

    /**
     * Creates a JwksLoader that loads JWKS from in-memory string content.
     *
     * @param jwksContent the JWKS content as a string
     * @return an instance of JwksLoader
     */
    public static JwksLoader createInMemoryLoader(@NonNull String jwksContent) {
        LOGGER.debug("Resolving key loader for in-memory JWKS data");
        JWKSKeyLoader keyLoader = new JWKSKeyLoader(jwksContent);
        LOGGER.debug("Successfully loaded %s keys", keyLoader.keySet().size());
        return keyLoader;
    }

}
