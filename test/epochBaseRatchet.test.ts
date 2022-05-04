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
import { ContentType, EMPTY_BYTE_ARRAY, ProtocolVersion } from "../src/constants";
import { BasicCredential } from "../src/credential";
import { Group } from "../src/group";
import { KEMPrivateKey } from "../src/hpke/base";
import { KeyPackage } from "../src/keypackage";
import { LenientHashRatchet } from "../src/keyschedule";
import { ProposalWrapper, Remove } from "../src/message";
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
    it("should create a new Group and encrypt a message to it", async () => {
        const [
            [signingPrivKeyA, hpkePrivKeyA, credentialA, keyPackageA],
            [signingPrivKeyB, hpkePrivKeyB, credentialB, keyPackageB]
        ] = await Promise.all([
            makeKeyPackage("@alice:example.org"),
            makeKeyPackage("@bob:example.org")
        ]);

        const [groupA, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB],
        );

        const [, groupB] = await Group.createFromWelcome(welcome, { bob1: [keyPackageB, hpkePrivKeyB] });


        expect(groupB.secrets).toEqual(groupA.secrets);

        const message = stringToUint8Array("message1");
        const mlsCiphertext = await groupA.encrypt(message, EMPTY_BYTE_ARRAY, signingPrivKeyA);
        expect((await groupA.decrypt(mlsCiphertext)).content).toEqual(message);
        expect((await groupB.decrypt(mlsCiphertext)).content).toEqual(message);

    });

    it("should decrypt messages using old base ratchets", async () => {
        // Create Keypackages
        const [
            [signingPrivKeyA, hpkePrivKeyA, credentialA, keyPackageA],
            [signingPrivKeyB, hpkePrivKeyB, credentialB, keyPackageB],
            [signingPrivKeyC, hpkePrivKeyC, credentialC, keyPackageC],
        ] = await Promise.all([
            makeKeyPackage("@alice:example.org"),
            makeKeyPackage("@bob:example.org"),
            makeKeyPackage("@carol:example.org"),
        ]);

        // Create Group
        let [groupA, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB, keyPackageC],
        );

        // Create Group from Welcome
        let [[keyB, groupB], [keyC, groupC]] = await Promise.all([
            Group.createFromWelcome(welcome, { bob1: [keyPackageB, hpkePrivKeyB] }),
            Group.createFromWelcome(welcome, { carol1: [keyPackageC, hpkePrivKeyC] }),
        ]);

        const message = stringToUint8Array("message");
        const mlsCiphertext = await groupA.encrypt(message, EMPTY_BYTE_ARRAY, signingPrivKeyA);
        expect((await groupA.decrypt(mlsCiphertext)).content).toEqual(message);
        expect((await groupB.decrypt(mlsCiphertext)).content).toEqual(message);
        expect((await groupC.decrypt(mlsCiphertext)).content).toEqual(message);

        // Save EpochBaseRatchet for each group
        const senderDataSecret = groupA.secrets.senderDataSecret

        let epochBaseRatchetsA = []
        let hashRatchetsA = groupA.getHashRatchets
        for (let node in hashRatchetsA) {
            epochBaseRatchetsA.push({
                "node": +node,
                "fstRatchet": hashRatchetsA[node][0].serializeMinimal(),
                "sndRatchet": hashRatchetsA[node][1].serializeMinimal()
            })
        }

        let epochBaseRatchetsB = []
        let hashRatchetsB = groupB.getHashRatchets
        for (let node in hashRatchetsB) {
            epochBaseRatchetsB.push({
                "node": +node,
                "fstRatchet": hashRatchetsB[node][0].serializeMinimal(),
                "sndRatchet": hashRatchetsB[node][1].serializeMinimal()
            })
        }

        let epochBaseRatchetsC = []
        let hashRatchetsC = groupC.getHashRatchets
        for (let node in hashRatchetsC) {
            epochBaseRatchetsC.push({
                "node": +node,
                "fstRatchet": hashRatchetsC[node][0].serializeMinimal(),
                "sndRatchet": hashRatchetsC[node][1].serializeMinimal()
            })
        }

        // Create Commit to remove C
        const [mlsCiphertext1, , ,] = await groupA.commit(
            [new ProposalWrapper(new Remove(2))],
            credentialA,
            signingPrivKeyA,
        );

        // Apply Commit
        await Promise.all([
            groupB.applyCommit(await groupB.decrypt(mlsCiphertext1)),
        ]);

        // Now, all members should be able to decrypt the messages form the last epoch
        const ratchet = mlsCiphertext.contentType == ContentType.Application ? "sndRatchet" : "fstRatchet";

        const plaintextA = await groupA.decrypt(
            mlsCiphertext,
            async (sender) => {
                for (let baseRatchet of epochBaseRatchetsA) {
                    if (baseRatchet["node"] === sender) {
                        let result = LenientHashRatchet.fromSerializedMinimal(baseRatchet[ratchet])
                        return result
                    }
                }
                throw new Error(`Ratchet for sender ${sender} not found in baseRatchets`)
            },
            senderDataSecret
        )

        expect(plaintextA.content).toEqual(message)

        const plaintextB = await groupB.decrypt(
            mlsCiphertext,
            async (sender) => {
                for (let baseRatchet of epochBaseRatchetsB) {
                    if (baseRatchet["node"] === sender) {
                        return LenientHashRatchet.fromSerializedMinimal(baseRatchet[ratchet])
                    }
                }
                throw new Error(`Ratchet for sender ${sender} not found in baseRatchets`)
            },
            senderDataSecret
        )

        expect(plaintextB.content).toEqual(message)

        const plaintextC = await groupC.decrypt(
            mlsCiphertext,
            async (sender) => {
                for (let baseRatchet of epochBaseRatchetsC) {
                    if (baseRatchet["node"] === sender) {
                        return LenientHashRatchet.fromSerializedMinimal(baseRatchet[ratchet])
                    }
                }
                throw new Error(`Ratchet for sender ${sender} not found in baseRatchets`)
            },
            senderDataSecret
        )

        expect(plaintextC.content).toEqual(message)

    });

});
