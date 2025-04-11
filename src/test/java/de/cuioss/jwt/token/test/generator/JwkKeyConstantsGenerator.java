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
package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.impl.CollectionGenerator;
import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.json.JsonObjectBuilder;

import java.math.BigInteger;
import java.util.Base64;
import java.util.List;

public class JwkKeyConstantsGenerator implements TypedGenerator<JsonObject> {

    private final TypedGenerator<String> keyTypeGenerator = Generators.fixedValues("RSA", "EC");
    private final TypedGenerator<String> publicKeyUseGenerator = Generators.fixedValues("sig", "enc");
    private final TypedGenerator<String> keyOperationsGenerator = Generators.fixedValues("sign", "verify", "encrypt", "decrypt");
    private final TypedGenerator<String> algorithmGenerator = Generators.fixedValues("RS256", "ES256");
    private final TypedGenerator<String> keyIdGenerator = Generators.nonBlankStrings();
    private final CollectionGenerator<Byte> byteGenerator = Generators.asCollectionGenerator(Generators.bytes());
    private final TypedGenerator<String> bigIntegerAsBase64 = () -> Base64.getUrlEncoder().encodeToString(BigInteger.valueOf(Generators.longs().next()).toByteArray());

    @Override
    public JsonObject next() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("kty", keyTypeGenerator.next());
        builder.add("use", publicKeyUseGenerator.next());
        builder.add("key_ops", Json.createArrayBuilder().add(keyOperationsGenerator.next()));
        builder.add("alg", algorithmGenerator.next());
        builder.add("kid", keyIdGenerator.next());
        builder.add("x", bigIntegerAsBase64.next());
        builder.add("y", bigIntegerAsBase64.next());
        builder.add("crv", "P-256");
        builder.add("n", bigIntegerAsBase64.next());
        builder.add("e", bigIntegerAsBase64.next());
        builder.add("d", Base64.getUrlEncoder().encodeToString(generateByteArray()));
        builder.add("p", bigIntegerAsBase64.next());
        builder.add("q", bigIntegerAsBase64.next());
        builder.add("keys", generateKeysArray());
        return builder.build();
    }

    private JsonArrayBuilder generateKeysArray() {
        JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        for (int i = 0; i < 3; i++) { // Generiere 3 Schlüssel für das Array
            arrayBuilder.add(nextSingleKey());
        }
        return arrayBuilder;
    }

    private JsonObject nextSingleKey() {
        JsonObjectBuilder builder = Json.createObjectBuilder();
        builder.add("kty", keyTypeGenerator.next());
        builder.add("use", publicKeyUseGenerator.next());
        builder.add("key_ops", Json.createArrayBuilder().add(keyOperationsGenerator.next()));
        builder.add("alg", algorithmGenerator.next());
        builder.add("kid", keyIdGenerator.next());
        builder.add("x", bigIntegerAsBase64.next());
        builder.add("y", bigIntegerAsBase64.next());
        builder.add("crv", "P-256");
        builder.add("n", bigIntegerAsBase64.next());
        builder.add("e", bigIntegerAsBase64.next());
        builder.add("d", Base64.getUrlEncoder().encodeToString(generateByteArray()));
        builder.add("p", bigIntegerAsBase64.next());
        builder.add("q", bigIntegerAsBase64.next());
        return builder.build();
    }

    private byte[] generateByteArray() {
        List<Byte> byteList = byteGenerator.list();
        byte[] byteArray = new byte[byteList.size()];
        for (int i = 0; i < byteList.size(); i++) {
            byteArray[i] = byteList.get(i);
        }
        return byteArray;
    }

    @Override
    public Class<JsonObject> getType() {
        return JsonObject.class;
    }
}