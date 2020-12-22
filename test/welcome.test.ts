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
import {stringToUint8Array} from "../src/util";
import {
    EMPTY_BYTE_ARRAY,
    SignatureScheme,
    CredentialType,
    ProtocolVersion,
} from "../src/constants";
import {BasicCredential, Credential} from "../src/credential";
import {GroupInfo, Welcome} from "../src/welcome";
import {KeyPackage} from "../src/keypackage";

describe("welcome", () => {
    it("should encrypt and decrypt", async () => {
        const [senderPrivKey, senderPubKey] =
            await cipherSuite.signatureScheme.generateKeyPair();
        const groupInfo = await GroupInfo.create(
            EMPTY_BYTE_ARRAY, 0, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, [],
            EMPTY_BYTE_ARRAY, 0, senderPrivKey,
        );

        const [recipSigningPrivKey, recipSigningPubKey] =
            await cipherSuite.signatureScheme.generateKeyPair();
        const credential = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                cipherSuite.signatureSchemeId,
                await recipSigningPubKey.serialize(),
            ),
        );
        const [hpkePrivKey, hpkePubKey] = await cipherSuite.hpke.kem.generateKeyPair();
        const keyPackage = await KeyPackage.create(
            ProtocolVersion.Mls10,
            cipherSuite,
            await hpkePubKey.serialize(),
            credential,
            [],
            recipSigningPrivKey,
        );

        const welcome = await Welcome.create(
            cipherSuite,
            new Uint8Array(cipherSuite.hpke.kdf.extractLength),
            groupInfo,
            [{keyPackage, pathSecret: new Uint8Array(cipherSuite.hpke.kdf.extractLength)}],
        );

        const [receivedGroupSecrets, receivedGroupInfo, keyId] = await welcome.decrypt(
            {"key": [keyPackage, hpkePrivKey]},
        );
        expect(receivedGroupInfo).toEqual(groupInfo);
        expect(keyId).toEqual("key");
        expect(await receivedGroupInfo.checkSignature(senderPubKey)).toBe(true);
        expect(receivedGroupSecrets.joinerSecret).toEqual(new Uint8Array(cipherSuite.hpke.kdf.extractLength));
        expect(receivedGroupSecrets.pathSecret).toEqual(new Uint8Array(cipherSuite.hpke.kdf.extractLength));
    });
});
