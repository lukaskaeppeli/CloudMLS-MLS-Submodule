/*
Copyright 2020 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import {Ed25519} from "../src/signatures";
import {concatUint8Array, stringToUint8Array} from "../src/util";
import {Credential} from "../src/credential";
import * as tlspl from "../src/tlspl";

describe("credential", () => {
    it("should verify", async () => {
        const [privKey, pubKey] = await Ed25519.generateKeyPair();

        const encodedCredential = concatUint8Array([
            Uint8Array.from([0, 1, 0, 18]),
            stringToUint8Array("@alice:example.org"),
            Uint8Array.from([8, 7, 0, 32]),
            await pubKey.serialize(),
        ]);

        const [[credential], ] = tlspl.decode([Credential.decode], encodedCredential);

        const signature: Uint8Array = await privKey.sign(Uint8Array.from([1, 2, 3]));
        expect(await credential.verify(Uint8Array.from([1, 2, 3]), signature)).toBe(true);
        expect(await credential.verify(Uint8Array.from([1, 2, 5]), signature)).toBe(false);
    });
    it("should encode and decode", async () => {
        const [, pubKey] = await Ed25519.generateKeyPair();

        const encodedCredential = concatUint8Array([
            Uint8Array.from([0, 1, 0, 18]),
            stringToUint8Array("@alice:example.org"),
            Uint8Array.from([8, 7, 0, 32]),
            await pubKey.serialize(),
        ]);

        const [[credential], ] = tlspl.decode([Credential.decode], encodedCredential);

        expect(tlspl.encode([credential.encoder])).toEqual(encodedCredential);
    });
});
