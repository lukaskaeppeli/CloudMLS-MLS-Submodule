/*
Copyright 2021 The Matrix.org Foundation C.I.C.

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

import {Group} from "../src/group";
import {BasicCredential} from "../src/credential";
import {KeyPackage} from "../src/keypackage";
import {mls10_128_DhKemX25519Aes128GcmSha256Ed25519 as cipherSuite} from "../src/ciphersuite";
import {ProtocolVersion} from "../src/constants";
import {stringToUint8Array} from "../src/util";
import {Remove, ProposalWrapper} from "../src/message";

// create a key paackage for a user with a new signing and HPKE key
async function makeKeyPackage(userId: string) {
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
    it("should create a new group and welcome initial members", async () => {
        const [
            [signingPrivKeyA, hpkePrivKeyA, credentialA, keyPackageA],
            [signingPrivKeyB, hpkePrivKeyB, credentialB, keyPackageB],
            [signingPrivKeyC, hpkePrivKeyC, credentialC, keyPackageC],
            [signingPrivKeyD, hpkePrivKeyD, credentialD, keyPackageD],
            [signingPrivKeyE, hpkePrivKeyE, credentialE, keyPackageE],
            [signingPrivKeyF, hpkePrivKeyF, credentialF, keyPackageF],
        ] = await Promise.all([
            makeKeyPackage("@alice:example.org"),
            makeKeyPackage("@bob:example.org"),
            makeKeyPackage("@carol:example.org"),
            makeKeyPackage("@dan:example.org"),
            makeKeyPackage("@erin:example.org"),
            makeKeyPackage("@frank:example.org"),
        ]);

        const [groupA, mlsPlaintext, welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB, keyPackageC, keyPackageD, keyPackageE, keyPackageF],
        );

        const [[keyB, groupB], [keyC, groupC], [keyD, groupD], [keyE, groupE], [keyF, groupF]] = await Promise.all([
            Group.createFromWelcome(welcome, {bob1: [keyPackageB, hpkePrivKeyB]}),
            Group.createFromWelcome(welcome, {carol1: [keyPackageC, hpkePrivKeyC]}),
            Group.createFromWelcome(welcome, {dan1: [keyPackageD, hpkePrivKeyD]}),
            Group.createFromWelcome(welcome, {erin1: [keyPackageE, hpkePrivKeyE]}),
            Group.createFromWelcome(welcome, {frank1: [keyPackageF, hpkePrivKeyF]}),
        ]);
        expect(groupB.secrets).toEqual(groupA.secrets);
        expect(groupC.secrets).toEqual(groupA.secrets);
        expect(groupD.secrets).toEqual(groupA.secrets);
        expect(groupE.secrets).toEqual(groupA.secrets);
        expect(groupF.secrets).toEqual(groupA.secrets);
    });

    it("should arrive at the same state when creating or processing a commit", async () => {
        const [
            [signingPrivKeyA, hpkePrivKeyA, credentialA, keyPackageA],
            [signingPrivKeyB, hpkePrivKeyB, credentialB, keyPackageB],
            [signingPrivKeyC, hpkePrivKeyC, credentialC, keyPackageC],
            [signingPrivKeyD, hpkePrivKeyD, credentialD, keyPackageD],
            [signingPrivKeyE, hpkePrivKeyE, credentialE, keyPackageE],
            [signingPrivKeyF, hpkePrivKeyF, credentialF, keyPackageF],
        ] = await Promise.all([
            makeKeyPackage("@alice:example.org"),
            makeKeyPackage("@bob:example.org"),
            makeKeyPackage("@carol:example.org"),
            makeKeyPackage("@dan:example.org"),
            makeKeyPackage("@erin:example.org"),
            makeKeyPackage("@frank:example.org"),
        ]);

        const [groupA, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB, keyPackageC, keyPackageD, keyPackageE, keyPackageF],
        );

        const [[keyB, groupB], [keyC, groupC], [keyD, groupD], [keyE, groupE], [keyF, groupF]] = await Promise.all([
            Group.createFromWelcome(welcome, {bob1: [keyPackageB, hpkePrivKeyB]}),
            Group.createFromWelcome(welcome, {carol1: [keyPackageC, hpkePrivKeyC]}),
            Group.createFromWelcome(welcome, {dan1: [keyPackageD, hpkePrivKeyD]}),
            Group.createFromWelcome(welcome, {erin1: [keyPackageE, hpkePrivKeyE]}),
            Group.createFromWelcome(welcome, {frank1: [keyPackageF, hpkePrivKeyF]}),
        ]);

        const [mlsPlaintext, welcome2] = await groupA.commit(
            [new ProposalWrapper(new Remove(3))],
            credentialA,
            signingPrivKeyA,
        );

        await Promise.all([
            groupB.applyCommit(mlsPlaintext),
            groupC.applyCommit(mlsPlaintext),
            groupE.applyCommit(mlsPlaintext),
            groupF.applyCommit(mlsPlaintext),
        ]);

        expect(groupA.secrets).toEqual(groupB.secrets);
        expect(groupA.secrets).toEqual(groupC.secrets);
        expect(groupA.secrets).toEqual(groupE.secrets);
        expect(groupA.secrets).toEqual(groupF.secrets);
    });
});
