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
package de.cuioss.jwt.token.adapter;

/**
 * Interface defining standard claim names for JWT tokens.
 * This is a replacement for the org.eclipse.microprofile.jwt.Claims interface
 * to allow for migration from SmallRye JWT to JJWT without changing the existing code.
 *
 * @author Oliver Wolff
 */
public interface Claims {

    /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     */
    String iss = "iss";

    /**
     * The "sub" (subject) claim identifies the principal that is the subject of the JWT.
     */
    String sub = "sub";

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     */
    String aud = "aud";

    /**
     * The "exp" (expiration time) claim identifies the expiration time on or after which
     * the JWT MUST NOT be accepted for processing.
     */
    String exp = "exp";

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
     */
    String nbf = "nbf";

    /**
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     */
    String iat = "iat";

    /**
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     */
    String jti = "jti";

    /**
     * The "groups" claim identifies the groups that the JWT belongs to.
     */
    String groups = "groups";

    /**
     * The "email" claim identifies the email address of the JWT subject.
     */
    String email = "email";

    /**
     * The "preferred_username" claim identifies the preferred username of the JWT subject.
     */
    String preferred_username = "preferred_username";
}