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

import {x25519HkdfSha256} from "../src/hpke/dhkem";
import {x25519HkdfSha256Aes128Gcm} from "../src/hpke";
import {Ed25519} from "../src/signatures";
import {BasicCredential, Credential} from "../src/credential";
import {KeyPackage} from "../src/keypackage";
import {HPKECiphertext} from "../src/message";
import {SignatureScheme, ProtocolVersion, CipherSuite, CredentialType} from "../src/constants";
import {stringToUint8Array} from "../src/util";
import * as tlspl from "../src/tlspl";

describe("key package", () => {
    it("should encode, decode, and have a valid signature", async () => {
        const [signingPrivKey, signingPubKey] = await Ed25519.generateKeyPair();

        const credential = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                SignatureScheme.ed25519,
                await signingPubKey.serialize(),
            ),
        );

        const [, hpkePubKey] = await x25519HkdfSha256.generateKeyPair();

        const keyPackage: KeyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey.serialize(),
            credential,
            [],
            signingPrivKey,
        );

        const encodedKeyPackage: Uint8Array = tlspl.encode([keyPackage.encoder]);

        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedKeyPackage], ] = tlspl.decode([KeyPackage.decode], encodedKeyPackage);
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
        const [signingPrivKey, signingPubKey] = await Ed25519.generateKeyPair();

        const credential = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                SignatureScheme.ed25519,
                await signingPubKey.serialize(),
            ),
        );

        const [hpkePrivKey, hpkePubKey] = await x25519HkdfSha256.generateKeyPair();

        const keyPackage: KeyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey.serialize(),
            credential,
            [],
            signingPrivKey,
        );

        const encodedKeyPackage: Uint8Array = tlspl.encode([keyPackage.encoder]);

        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedKeyPackage], ] = tlspl.decode([KeyPackage.decode], encodedKeyPackage);

        const ciphertext = await HPKECiphertext.encrypt(
            x25519HkdfSha256Aes128Gcm,
            await decodedKeyPackage.getHpkeKey(),
            Uint8Array.from([1, 2, 3]), Uint8Array.from([4, 5, 6]),
        );

        expect(await ciphertext.decrypt(
            x25519HkdfSha256Aes128Gcm,
            hpkePrivKey,
            Uint8Array.from([1, 2, 3]),
        )).toEqual(Uint8Array.from([4, 5, 6]));
    });
});
