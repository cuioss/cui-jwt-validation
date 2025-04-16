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
package de.cuioss.jwt.token.flow;

import lombok.Builder;
import lombok.Value;

/**
 * Configuration class for the TokenFactory.
 * <p>
 * This class provides configuration options for the TokenFactory, such as
 * maximum token size, maximum payload size, and logging behavior.
 */
@Builder
@Value
public class TokenFactoryConfig {

    /**
     * Maximum size of a JWT token in bytes to prevent overflow attacks.
     */
    @Builder.Default
    int maxTokenSize = NonValidatingJwtParser.DEFAULT_MAX_TOKEN_SIZE;

    /**
     * Maximum size of decoded JSON payload in bytes.
     */
    @Builder.Default
    int maxPayloadSize = NonValidatingJwtParser.DEFAULT_MAX_PAYLOAD_SIZE;

    /**
     * Flag to control whether warnings are logged when decoding fails.
     */
    @Builder.Default
    boolean logWarningsOnDecodeFailure = true;
}