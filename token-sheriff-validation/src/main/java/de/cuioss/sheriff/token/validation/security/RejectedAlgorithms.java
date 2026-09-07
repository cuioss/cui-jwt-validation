/*
 * Copyright © 2025-present CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.sheriff.token.validation.security;

import java.util.List;

/**
 * The algorithms this package refuses outright, defined once.
 * <p>
 * The symmetric MAC algorithms and {@code "none"} are never legitimate for the asymmetric key
 * material (RSA, EC, OKP) this library processes, so both {@link SignatureAlgorithmPreferences}
 * and {@link JwkAlgorithmPreferences} reject them. Holding the list here rather than once per
 * class is what keeps the two rejections from drifting apart: a member added to one copy but not
 * the other would leave a gate that rejects an algorithm its sibling still accepts.
 *
 * @since 1.0
 * @author Oliver Wolff
 */
final class RejectedAlgorithms {

    /**
     * The rejected algorithm names, in the order they are documented.
     */
    static final List<String> VALUES = List.of("HS256", "HS384", "HS512", "none");

    private RejectedAlgorithms() {
    }
}
