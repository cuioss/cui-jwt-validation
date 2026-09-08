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
package de.cuioss.sheriff.token.client.token;

import com.dslplatform.json.CompiledJson;

import java.util.Optional;

/**
 * The OAuth 2.0 token endpoint <em>error</em> response (RFC 6749 §5.2), mapped down to the single
 * member the client acts on.
 * <p>
 * RFC 6749 §5.2 also defines {@code error_description} and {@code error_uri}, and authorization
 * servers add members of their own. None of them is mapped here on purpose: the only decision this
 * response drives is whether the server attributed the refusal to the presented credential, which the
 * {@code error} code alone answers. Every unmapped member is skipped by the parser, so an
 * authorization server that returns a large or hostile {@code error_description} contributes nothing
 * that could reach a log appender or an exception message through this type.
 * <p>
 * Parsing uses DSL-JSON's compile-time {@code @CompiledJson} mapping. The field is {@code public}
 * because DSL-JSON class-based deserialization requires it; after deserialization the object is
 * treated as read-only and callers should use {@link #getError()}.
 *
 * @since 1.0
 * @author Oliver Wolff
 * @see <a href="https://www.rfc-editor.org/rfc/rfc6749#section-5.2">RFC 6749 §5.2 - Error Response</a>
 */
@CompiledJson
@SuppressWarnings("java:S1104") // Public field required by DSL-JSON @CompiledJson for class-based deserialization
public class TokenErrorResponse {

    /** The RFC 6749 §5.2 {@code error} code, e.g. {@code invalid_grant}. */
    public String error;

    /**
     * @return the {@code error} code, or {@link Optional#empty()} when the response carried no
     *         {@code error} member
     */
    public Optional<String> getError() {
        return Optional.ofNullable(error);
    }
}
