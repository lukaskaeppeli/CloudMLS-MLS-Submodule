/*
Copyright 2022 Lukas Käppeli

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

import { mls10_128_DhKemX25519Aes128GcmSha256Ed25519 as cipherSuite } from "../src/ciphersuite";
import { EMPTY_BYTE_ARRAY, ProtocolVersion } from "../src/constants";
import { BasicCredential } from "../src/credential";
import { Group } from "../src/group";
import { KEMPrivateKey } from "../src/hpke/base";
import { KeyPackage } from "../src/keypackage";
import { SigningPrivateKey } from "../src/signatures";
import { stringToUint8Array } from "../src/util";

// create a key package for a user with a new signing and HPKE key
async function makeKeyPackage(userId: string): Promise<[SigningPrivateKey, KEMPrivateKey, BasicCredential, KeyPackage]> {
    const [signingPrivKey, signingPubKey] =
        await cipherSuite.signatureScheme.generateKeyPair();
    const credential = new BasicCredential(
        stringToUint8Array(userId),
        cipherSuite.signatureSchemeId,
        await signingPubKey.serialize(),
    );
    const [hpkePrivKey, hpkePubKey] =
        await cipherSuite.hpke.kem.generateKeyPair();
    const keyPackage = await KeyPackage.create(
        ProtocolVersion.Mls10,
        cipherSuite,
        await hpkePubKey.serialize(),
        credential,
        [],
        signingPrivKey,
    );
    return [signingPrivKey, hpkePrivKey, credential, keyPackage];
}

describe("Group", () => {

    it("should encrypt and decrypt after serialization", async () => {
        // Create Keypackages
        const [
            [signingPrivKeyA, hpkePrivKeyA, credentialA, keyPackageA],
            [signingPrivKeyB, hpkePrivKeyB, credentialB, keyPackageB]
        ] = await Promise.all([
            makeKeyPackage("@alice:example.org"),
            makeKeyPackage("@bob:example.org"),
        ]);

        // Create Group
        const [groupA, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB],
        );

        // Create Group from Welcome
        const [keyB, groupB] = await Group.createFromWelcome(welcome, { bob1: [keyPackageB, hpkePrivKeyB] })
        expect(groupA.secrets).toEqual(groupB.secrets);

        // Serialize all groups
        let [serialized_A, serialized_B] = await Promise.all([
            groupA.serialize(),
            groupB.serialize(),
        ]);

        // Create groups from serialized
        let [groupA_ser, groupB_ser] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B),
        ])


        const message1 = stringToUint8Array("message1");

        // Encrypt / Decrypt (NON-SERIALIZED)
        const mlsCiphertextM1 = await groupA.encrypt(message1, EMPTY_BYTE_ARRAY, signingPrivKeyA);
        expect(((await groupB.decrypt(mlsCiphertextM1))).content).toEqual(message1);

        // Encrypt / Decrypt (SERIALIZED)
        const mlsCiphertextM1_ser = await groupA_ser.encrypt(message1, EMPTY_BYTE_ARRAY, signingPrivKeyA);
        expect(((await groupB_ser.decrypt(mlsCiphertextM1_ser))).content).toEqual(message1);

        // Serialize again
        [serialized_A, serialized_B] = await Promise.all([
            groupA.serialize(),
            groupB.serialize()
        ]);

        // Create from serialized again
        [groupA_ser, groupB_ser] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B),
        ])

        const message2 = stringToUint8Array("message2");

        // Encrypt / Decrypt again (NON-SERIALIZED)
        const mlsCiphertextM2 = await groupB.encrypt(message2, EMPTY_BYTE_ARRAY, signingPrivKeyB);
        expect((await groupA.decrypt(mlsCiphertextM2)).content).toEqual(message2);


        // Encrypt / Decrypt again (SERIALIZED)
        const mlsCiphertextM2_ser = await groupB_ser.encrypt(message2, EMPTY_BYTE_ARRAY, signingPrivKeyB);
        expect((await groupA_ser.decrypt(mlsCiphertextM2_ser)).content).toEqual(message2);

        // Serialize again
        [serialized_A, serialized_B] = await Promise.all([
            groupA.serialize(),
            groupB.serialize()
        ]);

        // Create from serialized again
        [groupA_ser, groupB_ser] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B)
        ])

        const message3 = stringToUint8Array("message3");

        // Encrypt / Decrypt a last time (NON-SERIALIZED)
        const mlsCiphertextM3 = await groupA.encrypt(message3, EMPTY_BYTE_ARRAY, signingPrivKeyA);
        expect((await groupB.decrypt(mlsCiphertextM3)).content).toEqual(message3);

        // Encrypt / Decrypt a last time (SERIALIZED)
        const mlsCiphertextM3_ser = await groupA_ser.encrypt(message3, EMPTY_BYTE_ARRAY, signingPrivKeyA);
        expect((await groupB_ser.decrypt(mlsCiphertextM3_ser)).content).toEqual(message3);


        // Serialize again
        [serialized_A, serialized_B] = await Promise.all([
            groupA.serialize(),
            groupB.serialize()
        ]);

        // Create from serialized again
        [groupA_ser, groupB_ser] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B)
        ])

        const message4 = stringToUint8Array("message3");

        // Encrypt / Decrypt a last time (NON-SERIALIZED)
        const mlsCiphertextM4 = await groupB.encrypt(message4, EMPTY_BYTE_ARRAY, signingPrivKeyB);
        expect((await groupA.decrypt(mlsCiphertextM4)).content).toEqual(message4);

        // Encrypt / Decrypt a last time (SERIALIZED)
        const mlsCiphertextM4_ser = await groupB_ser.encrypt(message4, EMPTY_BYTE_ARRAY, signingPrivKeyB);
        expect((await groupA_ser.decrypt(mlsCiphertextM4_ser)).content).toEqual(message4);
    });
});
