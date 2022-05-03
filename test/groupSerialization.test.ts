import { Group } from "../src/group";
import { BasicCredential } from "../src/credential";
import { KeyPackage } from "../src/keypackage";
import { mls10_128_DhKemX25519Aes128GcmSha256Ed25519 as cipherSuite } from "../src/ciphersuite";
import { EMPTY_BYTE_ARRAY, ProtocolVersion } from "../src/constants";
import { stringToUint8Array } from "../src/util";
import { Add, Remove, ProposalWrapper } from "../src/message";
import { SigningPrivateKey } from "../src/signatures";
import { KEMPrivateKey } from "../src/hpke/base";

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

        const [groupA, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB, keyPackageC, keyPackageD, keyPackageE, keyPackageF],
        );

        const [[, groupB], [, groupC], [, groupD], [, groupE], [, groupF]] = await Promise.all([
            Group.createFromWelcome(welcome, { bob1: [keyPackageB, hpkePrivKeyB] }),
            Group.createFromWelcome(welcome, { carol1: [keyPackageC, hpkePrivKeyC] }),
            Group.createFromWelcome(welcome, { dan1: [keyPackageD, hpkePrivKeyD] }),
            Group.createFromWelcome(welcome, { erin1: [keyPackageE, hpkePrivKeyE] }),
            Group.createFromWelcome(welcome, { frank1: [keyPackageF, hpkePrivKeyF] }),
        ]);
        expect(groupB.secrets).toEqual(groupA.secrets);
        expect(groupC.secrets).toEqual(groupA.secrets);
        expect(groupD.secrets).toEqual(groupA.secrets);
        expect(groupE.secrets).toEqual(groupA.secrets);
        expect(groupF.secrets).toEqual(groupA.secrets);
    });

    it("serialize groups and restore them correctly, then apply a commit", async () => {
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

        const [groupA0, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB, keyPackageC, keyPackageD, keyPackageE, keyPackageF],
        );

        const [[keyB, groupB0], [keyC, groupC0], [keyD, groupD0], [keyE, groupE0], [keyF, groupF0]] = await Promise.all([
            Group.createFromWelcome(welcome, { bob1: [keyPackageB, hpkePrivKeyB] }),
            Group.createFromWelcome(welcome, { carol1: [keyPackageC, hpkePrivKeyC] }),
            Group.createFromWelcome(welcome, { dan1: [keyPackageD, hpkePrivKeyD] }),
            Group.createFromWelcome(welcome, { erin1: [keyPackageE, hpkePrivKeyE] }),
            Group.createFromWelcome(welcome, { frank1: [keyPackageF, hpkePrivKeyF] }),
        ]);

        const [serialized_A, serialized_B, serialized_C, serialized_D, serialized_E, serialized_F] = await Promise.all([
            groupA0.serialize(),
            groupB0.serialize(),
            groupC0.serialize(),
            groupD0.serialize(),
            groupE0.serialize(),
            groupF0.serialize(),
        ]);

        const [groupA, groupB, groupC, groupD, groupE, groupF] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B),
            Group.fromSerialized(serialized_C),
            Group.fromSerialized(serialized_D),
            Group.fromSerialized(serialized_E),
            Group.fromSerialized(serialized_F),
        ])

        const [, mlsPlaintext1, ,] = await groupA.commit(
            [new ProposalWrapper(new Remove(3))],
            credentialA,
            signingPrivKeyA,
        );

        await Promise.all([
            groupB.applyCommit(mlsPlaintext1),
            groupC.applyCommit(mlsPlaintext1),
            groupE.applyCommit(mlsPlaintext1),
            groupF.applyCommit(mlsPlaintext1),
        ]);

        expect(groupA.secrets).toEqual(groupB.secrets);
        expect(groupA.secrets).toEqual(groupC.secrets);
        expect(groupA.secrets).toEqual(groupE.secrets);
        expect(groupA.secrets).toEqual(groupF.secrets);

        // D was removed, so he shouldn't be able to apply the commit
        await expect(groupD.applyCommit(mlsPlaintext1)).rejects.toThrow("Could not decrypt path secret");

        const [, mlsPlaintext2, welcome2,] = await groupB.commit(
            [
                new ProposalWrapper(new Remove(4)),
                new ProposalWrapper(new Add(keyPackageD)),
            ],
            credentialB,
            signingPrivKeyB,
        );

        await Promise.all([
            groupA.applyCommit(mlsPlaintext2),
            groupC.applyCommit(mlsPlaintext2),
            groupF.applyCommit(mlsPlaintext2),
        ]);

        expect(groupA.secrets).toEqual(groupB.secrets);
        expect(groupA.secrets).toEqual(groupC.secrets);
        expect(groupA.secrets).toEqual(groupF.secrets);

        const [, groupD2] = await Group.createFromWelcome(
            welcome2, { dan1: [keyPackageD, hpkePrivKeyD] },
        );

        expect(groupA.secrets).toEqual(groupD2.secrets);
    });

    it("should encrypt and decrypt after serialization", async () => {
        // Create Keypackages
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

        // Create Group
        let [groupA, , welcome] = await Group.createNew(
            ProtocolVersion.Mls10,
            cipherSuite,
            stringToUint8Array("groupid"),
            credentialA,
            signingPrivKeyA,
            [keyPackageB, keyPackageC, keyPackageD, keyPackageE, keyPackageF],
        );

        // Create Group from Welcome
        let [[keyB, groupB], [keyC, groupC], [keyD, groupD], [keyE, groupE], [keyF, groupF]] = await Promise.all([
            Group.createFromWelcome(welcome, { bob1: [keyPackageB, hpkePrivKeyB] }),
            Group.createFromWelcome(welcome, { carol1: [keyPackageC, hpkePrivKeyC] }),
            Group.createFromWelcome(welcome, { dan1: [keyPackageD, hpkePrivKeyD] }),
            Group.createFromWelcome(welcome, { erin1: [keyPackageE, hpkePrivKeyE] }),
            Group.createFromWelcome(welcome, { frank1: [keyPackageF, hpkePrivKeyF] }),
        ]);

        // Create Commit to remove D
        const [mlsCiphertext1, , ,] = await groupA.commit(
            [new ProposalWrapper(new Remove(3))],
            credentialA,
            signingPrivKeyA,
        );

        // Apply Commit
        await Promise.all([
            groupB.applyCommit(await groupB.decrypt(mlsCiphertext1)),
            groupC.applyCommit(await groupC.decrypt(mlsCiphertext1)),
            groupE.applyCommit(await groupE.decrypt(mlsCiphertext1)),
            groupF.applyCommit(await groupF.decrypt(mlsCiphertext1)),
        ]);

        expect(groupA.secrets).toEqual(groupB.secrets);
        expect(groupA.secrets).toEqual(groupC.secrets);
        expect(groupA.secrets).toEqual(groupE.secrets);
        expect(groupA.secrets).toEqual(groupF.secrets);

        // Serialize all groups
        let [serialized_A, serialized_B, serialized_C, serialized_D, serialized_E, serialized_F] = await Promise.all([
            groupA.serialize(),
            groupB.serialize(),
            groupC.serialize(),
            groupD.serialize(), //-> not in the group anymore
            groupE.serialize(),
            groupF.serialize(),
        ]);

        // Create groups from serialized
        [groupA, groupB, groupC, groupD, groupE, groupF] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B),
            Group.fromSerialized(serialized_C),
            Group.fromSerialized(serialized_D), //-> not in the group anymore
            Group.fromSerialized(serialized_E),
            Group.fromSerialized(serialized_F),
        ])

        // Encrypt / Decrypt
        const message1 = stringToUint8Array("message1");
        const mlsCiphertextM1 = await groupE.encrypt(message1, EMPTY_BYTE_ARRAY, signingPrivKeyE);
        expect((await groupA.decrypt(mlsCiphertextM1)).content).toEqual(message1);
        expect((await groupB.decrypt(mlsCiphertextM1)).content).toEqual(message1);
        expect((await groupC.decrypt(mlsCiphertextM1)).content).toEqual(message1);
        expect((await groupF.decrypt(mlsCiphertextM1)).content).toEqual(message1);

        // Serialize again
        [serialized_A, serialized_B, serialized_C, serialized_D, serialized_E, serialized_F] = await Promise.all([
            groupA.serialize(),
            groupB.serialize(),
            groupC.serialize(),
            groupD.serialize(),
            groupE.serialize(),
            groupF.serialize(),
        ]);

        // Create from serialized again
        [groupA, groupB, groupC, groupD, groupE, groupF] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B),
            Group.fromSerialized(serialized_C),
            Group.fromSerialized(serialized_D),
            Group.fromSerialized(serialized_E),
            Group.fromSerialized(serialized_F),
        ])

        // Encrypt / Decrypt again
        const message2 = stringToUint8Array("message2");
        const mlsCiphertextM2 = await groupA.encrypt(message2, EMPTY_BYTE_ARRAY, signingPrivKeyD);
        expect((await groupB.decrypt(mlsCiphertextM2)).content).toEqual(message2);
        expect((await groupC.decrypt(mlsCiphertextM2)).content).toEqual(message2);
        expect((await groupE.decrypt(mlsCiphertextM2)).content).toEqual(message2);
        expect((await groupF.decrypt(mlsCiphertextM2)).content).toEqual(message2);

        // Serialize again
        [serialized_A, serialized_B, serialized_C, serialized_D, serialized_E, serialized_F] = await Promise.all([
            groupA.serialize(),
            groupB.serialize(),
            groupC.serialize(),
            groupD.serialize(),
            groupE.serialize(),
            groupF.serialize(),
        ]);

        // Create from serialized again
        [groupA, groupB, groupC, groupD, groupE, groupF] = await Promise.all([
            Group.fromSerialized(serialized_A),
            Group.fromSerialized(serialized_B),
            Group.fromSerialized(serialized_C),
            Group.fromSerialized(serialized_D),
            Group.fromSerialized(serialized_E),
            Group.fromSerialized(serialized_F),
        ])

        // Encrypt / Decrypt a last time
        const message3 = stringToUint8Array("message3");
        const mlsCiphertextM3 = await groupF.encrypt(message3, EMPTY_BYTE_ARRAY, signingPrivKeyD);
        expect((await groupA.decrypt(mlsCiphertextM3)).content).toEqual(message3);
        expect((await groupB.decrypt(mlsCiphertextM3)).content).toEqual(message3);
        expect((await groupC.decrypt(mlsCiphertextM3)).content).toEqual(message3);
        expect((await groupE.decrypt(mlsCiphertextM3)).content).toEqual(message3);

    });
});
