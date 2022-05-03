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

import {mls10_128_DhKemX25519Aes128GcmSha256Ed25519 as cipherSuite} from "../src/ciphersuite";
import {BasicCredential} from "../src/credential";
import {KeyPackage, ParentHash} from "../src/keypackage";
import {HPKECiphertext} from "../src/message";
import {EMPTY_BYTE_ARRAY, SignatureScheme, ProtocolVersion} from "../src/constants";
import {stringToUint8Array} from "../src/util";
import * as tlspl from "../src/tlspl";

describe("key package", () => {
    it("should encode, decode, and have a valid signature", async () => {
        const [signingPrivKey, signingPubKey] =
            await cipherSuite.signatureScheme.generateKeyPair();

        const credential = new BasicCredential(
            stringToUint8Array("@alice:example.org"),
            SignatureScheme.ed25519,
            await signingPubKey.serialize(),
        );

        const [, hpkePubKey] =
            await cipherSuite.hpke.kem.generateKeyPair();

        const keyPackage: KeyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            cipherSuite,
            await hpkePubKey.serialize(),
            credential,
            [new ParentHash(EMPTY_BYTE_ARRAY)],
            signingPrivKey,
        );

        const encodedKeyPackage: Uint8Array = tlspl.encode([keyPackage.encoder]);

        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedKeyPackage], ] = tlspl.decode([KeyPackage.decode], encodedKeyPackage);
        expect(decodedKeyPackage.extensions.length).toEqual(1);
        expect(await decodedKeyPackage.checkSignature()).toBe(true);

        // if we mangle the signature, it shouldn't verify
        const badEncodedKeyPackage = new Uint8Array(encodedKeyPackage);
        const l = badEncodedKeyPackage.byteLength;
        badEncodedKeyPackage[l - 1] = badEncodedKeyPackage[l - 1] ^ 0xff;
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[badDecodedKeyPackage], ] = tlspl.decode([KeyPackage.decode], badEncodedKeyPackage);
        expect(await badDecodedKeyPackage.checkSignature()).toBe(false);
    });

    it("should encrypt to a key package", async () => {
        const [signingPrivKey, signingPubKey] =
            await cipherSuite.signatureScheme.generateKeyPair();

        const credential = new BasicCredential(
            stringToUint8Array("@alice:example.org"),
            SignatureScheme.ed25519,
            await signingPubKey.serialize(),
        );

        const [hpkePrivKey, hpkePubKey] =
            await cipherSuite.hpke.kem.generateKeyPair();

        const keyPackage: KeyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            cipherSuite,
            await hpkePubKey.serialize(),
            credential,
            [],
            signingPrivKey,
        );

        const encodedKeyPackage: Uint8Array = tlspl.encode([keyPackage.encoder]);

        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedKeyPackage], ] = tlspl.decode([KeyPackage.decode], encodedKeyPackage);

        const ciphertext = await HPKECiphertext.encrypt(
            cipherSuite.hpke,
            await decodedKeyPackage.getHpkeKey(),
            Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5, 6]),
        );

        expect(await ciphertext.decrypt(
            cipherSuite.hpke,
            hpkePrivKey,
            Uint8Array.from([1, 2, 3]),
        )).toEqual(Uint8Array.from([4, 5, 6]));
    });

    it("should encode the Lifetime extension correctly", async () => {
        const cipherSuite = cipherSuiteById[1]
        const [signingPrivKey, signingPubKey] = await cipherSuite.signatureScheme.generateKeyPair();
        const [hpkePrivKey, hpkePubKey] = await cipherSuite.hpke.kem.generateKeyPair();

        let credential = new BasicCredential(
            stringToUint8Array("TEST_ID"),
            cipherSuite.signatureSchemeId,
            await signingPubKey.serialize(),
        );

        // Create Lifetime for 30 Days, starting from now
        const now = new Date().getTime()
        const valid_until = now + (1000 * 3600 * 24 * 30)

        const lifetime = new Lifetime(now, valid_until)

        const keyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            cipherSuite,
            await hpkePubKey.serialize(),
            credential,
            [lifetime],
            signingPrivKey,
        );

        const enc_keyPackage = tlspl.encode([keyPackage.encoder])

        const [keypackage_decoded, _] = KeyPackage.decode(enc_keyPackage, 0)
        //console.log(keypackage_decoded)

        // Expect to be a valid keypackage
        expect(await keypackage_decoded.checkSignature()).toBe(true)
        
        const lifetime_decoded = keypackage_decoded.extensions[0] as Lifetime
        expect(lifetime_decoded.not_before).toEqual(now)
        expect(lifetime_decoded.not_after).toEqual(valid_until)
    });

});
