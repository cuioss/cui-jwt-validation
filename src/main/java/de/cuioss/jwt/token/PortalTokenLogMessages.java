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
package de.cuioss.jwt.token;

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Provides logging messages for the portal-authentication-token module.
 * All messages follow the format: PortalToken-[identifier]: [message]
 */
@UtilityClass
public final class PortalTokenLogMessages {

    private static final String PREFIX = "PortalToken";

    @UtilityClass
    public static final class INFO {
        public static final LogRecord CONFIGURED_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("Initializing JWKS lookup, jwks-endpoint='%s', refresh-interval='%s', issuer='%s'")
                .build();


    }

    @UtilityClass
    public static final class WARN {
        public static final LogRecord TOKEN_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(100)
                .template("Token exceeds maximum size limit of %s bytes, token will be rejected")
                .build();

        public static final LogRecord TOKEN_IS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("The given token was empty, request will be rejected")
                .build();

        public static final LogRecord COULD_NOT_PARSE_TOKEN = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(102)
                .template("Unable to parse token due to ParseException: %s")
                .build();

    }

}
