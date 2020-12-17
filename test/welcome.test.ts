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

import {stringToUint8Array} from "../src/util";
import {x25519HkdfSha256} from "../src/hpke/dhkem";
import {x25519HkdfSha256Aes128Gcm} from "../src/hpke";
import {
    EMPTY_BYTE_ARRAY,
    SignatureScheme,
    CredentialType,
    ProtocolVersion,
    CipherSuite,
} from "../src/constants";
import {BasicCredential, Credential} from "../src/credential";
import {GroupInfo, Welcome} from "../src/welcome";
import {KeyPackage} from "../src/keypackage";
import {Ed25519} from "../src/signatures";
import {sha256} from "../src/hash";

describe("welcome", () => {
    it("should encrypt and decrypt", async () => {
        const [senderPrivKey, senderPubKey] = await Ed25519.generateKeyPair();
        const groupInfo = await GroupInfo.create(
            EMPTY_BYTE_ARRAY, 0, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, [],
            EMPTY_BYTE_ARRAY, 0, senderPrivKey,
        );

        const [recipSigningPrivKey, recipSigningPubKey] = await Ed25519.generateKeyPair();
        const credential = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                SignatureScheme.ed25519,
                await recipSigningPubKey.serialize(),
            ),
        );
        const [hpkePrivKey, hpkePubKey] = await x25519HkdfSha256.generateKeyPair();
        const keyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey.serialize(),
            credential,
            [],
            recipSigningPrivKey,
        );

        const welcome = await Welcome.create(
            x25519HkdfSha256Aes128Gcm, sha256,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength),
            groupInfo,
            [{keyPackage, pathSecret: new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength)}],
        );

        const [receivedGroupSecrets, receivedGroupInfo, keyId] = await welcome.decrypt(
            x25519HkdfSha256Aes128Gcm, sha256, {"key": [keyPackage, hpkePrivKey]},
        );
        expect(receivedGroupInfo).toEqual(groupInfo);
        expect(keyId).toEqual("key");
        expect(await receivedGroupInfo.checkSignature(senderPubKey)).toBe(true);
        expect(receivedGroupSecrets.joinerSecret).toEqual(new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength));
        expect(receivedGroupSecrets.pathSecret).toEqual(new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength));
    });
});
