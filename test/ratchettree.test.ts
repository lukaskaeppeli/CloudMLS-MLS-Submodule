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
import {NodeData, RatchetTreeView} from "../src/ratchettree";
import {Extension, KeyPackage} from "../src/keypackage";
import {Add, Update, Remove} from "../src/message";
import {SignatureScheme, ProtocolVersion, CipherSuite, CredentialType} from "../src/constants";
import {stringToUint8Array} from "../src/util";
import {Tree} from "../src/lbbtree";
import * as tlspl from "../src/tlspl";

describe("Ratchet Tree", () => {
    it("should export and input", async () => {
        const [signingPrivKey0, signingPubKey0] = await Ed25519.generateKeyPair();
        const [signingPrivKey1, signingPubKey1] = await Ed25519.generateKeyPair();
        const [signingPrivKey2, signingPubKey2] = await Ed25519.generateKeyPair();
        const credential0 = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                SignatureScheme.ed25519,
                await signingPubKey0.serialize(),
            ),
        );
        const credential1 = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@bob:example.org"),
                SignatureScheme.ed25519,
                await signingPubKey1.serialize(),
            ),
        );
        const credential2 = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@carol:example.org"),
                SignatureScheme.ed25519,
                await signingPubKey1.serialize(),
            ),
        );

        const [hpkePrivKey0, hpkePubKey0] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey1, hpkePubKey1] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey2, hpkePubKey2] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey3, hpkePubKey3] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey4, hpkePubKey4] = await x25519HkdfSha256.generateKeyPair();

        const keyPackage0 = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey0.serialize(),
            credential0,
            [],
            signingPrivKey0,
        );
        const keyPackage1 = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey2.serialize(),
            credential1,
            [],
            signingPrivKey1,
        );
        const keyPackage2 = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey4.serialize(),
            credential2,
            [],
            signingPrivKey2,
        );

        const nodes: NodeData[] = [
            new NodeData(hpkePrivKey0, hpkePubKey0, [], credential0, undefined),
            new NodeData(hpkePrivKey1, hpkePubKey1, [], undefined, undefined),
            new NodeData(undefined, hpkePubKey2, [], credential1, undefined),
            new NodeData(undefined, hpkePubKey3, [], undefined, undefined),
            new NodeData(undefined, hpkePubKey4, [], credential2, undefined),
        ];
        nodes[3].unmergedLeaves.push(nodes[4]);
        const ratchetTreeView = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 0,
            new Tree<NodeData>(nodes),
            [keyPackage0, keyPackage1, keyPackage2],
        );

        const ratchetTreeExtension = await ratchetTreeView.toRatchetTreeExtension();
        const encodedExtension = tlspl.encode([ratchetTreeExtension.encoder]);
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedExtension], ] = tlspl.decode([Extension.decode], encodedExtension);
        const decodedRatchetTreeView = await RatchetTreeView.fromRatchetTreeExtension(
            x25519HkdfSha256Aes128Gcm, decodedExtension, keyPackage1,
            hpkePrivKey1,
        );

        const decodedTreeNodes = [...decodedRatchetTreeView.tree];
        expect(decodedTreeNodes.length).toBe(5);
        expect(decodedTreeNodes[0].privateKey).toEqual(undefined);
        expect(await decodedTreeNodes[0].publicKey.serialize())
            .toEqual(await hpkePubKey0.serialize());
        expect(decodedTreeNodes[0].unmergedLeaves).toEqual([]);
        expect(decodedTreeNodes[0].credential).toEqual(credential0);

        expect(decodedTreeNodes[1].privateKey).toEqual(undefined);
        expect(await decodedTreeNodes[1].publicKey.serialize())
            .toEqual(await hpkePubKey1.serialize());
        expect(decodedTreeNodes[1].unmergedLeaves).toEqual([]);
        expect(decodedTreeNodes[1].credential).toEqual(undefined);

        expect(decodedTreeNodes[2].privateKey).toEqual(hpkePrivKey1);
        expect(await decodedTreeNodes[2].publicKey.serialize())
            .toEqual(await hpkePubKey2.serialize());
        expect(decodedTreeNodes[2].unmergedLeaves).toEqual([]);
        expect(decodedTreeNodes[2].credential).toEqual(credential1);

        expect(decodedTreeNodes[3].privateKey).toEqual(undefined);
        expect(await decodedTreeNodes[3].publicKey.serialize())
            .toEqual(await hpkePubKey3.serialize());
        expect(decodedTreeNodes[3].unmergedLeaves).toEqual([decodedTreeNodes[4]]);
        expect(decodedTreeNodes[3].credential).toEqual(undefined);

        expect(decodedTreeNodes[4].privateKey).toEqual(undefined);
        expect(await decodedTreeNodes[4].publicKey.serialize())
            .toEqual(await hpkePubKey4.serialize());
        expect(decodedTreeNodes[4].unmergedLeaves).toEqual([]);
        expect(decodedTreeNodes[4].credential).toEqual(credential2);
    });

    it("should update path", async () => {
        const [signingPrivKey, signingPubKey] = await Ed25519.generateKeyPair();
        const credential = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                SignatureScheme.ed25519,
                await signingPubKey.serialize(),
            ),
        );
        async function makeKeyPackage(pubKey: Uint8Array): Promise<KeyPackage> {
            return await KeyPackage.create(
                ProtocolVersion.Mls10,
                CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                pubKey,
                credential,
                [],
                signingPrivKey,
            );
        }

        const [hpkePrivKey0, hpkePubKey0] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey1, hpkePubKey1] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey2, hpkePubKey2] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey3, hpkePubKey3] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey4, hpkePubKey4] = await x25519HkdfSha256.generateKeyPair();

        //     3
        //    / \
        //   1   \
        //  / \   \
        // 0   2   4

        const ratchetTreeView0v0 = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 0,
            new Tree<NodeData>([
                new NodeData(hpkePrivKey0, hpkePubKey0, [], undefined, undefined),
                new NodeData(hpkePrivKey1, hpkePubKey1, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey2, [], undefined, undefined),
                new NodeData(hpkePrivKey3, hpkePubKey3, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey4, [], undefined, undefined),
            ]),
            new Array(3),
        );
        const ratchetTreeView1v0 = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 1,
            new Tree<NodeData>([
                new NodeData(undefined, hpkePubKey0, [], undefined, undefined),
                new NodeData(hpkePrivKey1, hpkePubKey1, [], undefined, undefined),
                new NodeData(hpkePrivKey2, hpkePubKey2, [], undefined, undefined),
                new NodeData(hpkePrivKey3, hpkePubKey3, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey4, [], undefined, undefined),
            ]),
            new Array(3),
        );
        const ratchetTreeView2v0 = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 2,
            new Tree<NodeData>([
                new NodeData(undefined, hpkePubKey0, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey1, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey2, [], undefined, undefined),
                new NodeData(hpkePrivKey3, hpkePubKey3, [], undefined, undefined),
                new NodeData(hpkePrivKey4, hpkePubKey4, [], undefined, undefined),
            ]),
            new Array(3),
        );

        const [updatePath, commitSecret1, ratchetTreeView1v1] = await ratchetTreeView1v0.update(makeKeyPackage);
        expect(ratchetTreeView1v1.tree.root.data.privateKey).not.toEqual(hpkePrivKey3);
        expect(ratchetTreeView1v1.keyPackages[1]).toBeTruthy();

        const [commitSecret0, ratchetTreeView0v1] = await ratchetTreeView0v0.applyUpdatePath(1, updatePath);
        expect(commitSecret0).toEqual(commitSecret1);
        expect(ratchetTreeView0v1.tree.root.data.privateKey).toEqual(ratchetTreeView1v1.tree.root.data.privateKey);
        expect(ratchetTreeView0v1.keyPackages[1]).toEqual(ratchetTreeView1v1.keyPackages[1]);

        const [commitSecret2, ratchetTreeView2v1] = await ratchetTreeView2v0.applyUpdatePath(1, updatePath);
        expect(commitSecret2).toEqual(commitSecret1);
        expect(ratchetTreeView2v1.tree.root.data.privateKey).toEqual(ratchetTreeView1v1.tree.root.data.privateKey);
        expect(ratchetTreeView2v1.keyPackages[1]).toEqual(ratchetTreeView1v1.keyPackages[1]);
    });

    it("should remove, update, and add", async () => {
        const [, signingPubKeyA] = await Ed25519.generateKeyPair();
        const credentialA = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@alice:example.org"),
                SignatureScheme.ed25519,
                await signingPubKeyA.serialize(),
            ),
        );
        const [signingPrivKeyB, signingPubKeyB] = await Ed25519.generateKeyPair();
        const credentialB = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@bob:example.org"),
                SignatureScheme.ed25519,
                await signingPubKeyB.serialize(),
            ),
        );
        const [, signingPubKeyC] = await Ed25519.generateKeyPair();
        const credentialC = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@carol:example.org"),
                SignatureScheme.ed25519,
                await signingPubKeyC.serialize(),
            ),
        );
        const [signingPrivKeyD, signingPubKeyD] = await Ed25519.generateKeyPair();
        const credentialD = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@dave:example.org"),
                SignatureScheme.ed25519,
                await signingPubKeyD.serialize(),
            ),
        );
        const [signingPrivKeyE, signingPubKeyE] = await Ed25519.generateKeyPair();
        const credentialE = new Credential(
            CredentialType.Basic,
            new BasicCredential(
                stringToUint8Array("@emma:example.org"),
                SignatureScheme.ed25519,
                await signingPubKeyE.serialize(),
            ),
        );

        const [hpkePrivKey0, hpkePubKey0] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey1, hpkePubKey1] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey2, hpkePubKey2] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey3, hpkePubKey3] = await x25519HkdfSha256.generateKeyPair();
        const [hpkePrivKey4, hpkePubKey4] = await x25519HkdfSha256.generateKeyPair();

        //     3
        //    / \
        //   1   \
        //  / \   \
        // 0   2   4

        const ratchetTreeView0v0 = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 0,
            new Tree<NodeData>([
                new NodeData(hpkePrivKey0, hpkePubKey0, [], credentialA, undefined),
                new NodeData(hpkePrivKey1, hpkePubKey1, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey2, [], credentialB, undefined),
                new NodeData(hpkePrivKey3, hpkePubKey3, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey4, [], credentialC, undefined),
            ]),
            new Array(3),
        );
        const ratchetTreeView1v0 = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 1,
            new Tree<NodeData>([
                new NodeData(undefined, hpkePubKey0, [], credentialA, undefined),
                new NodeData(hpkePrivKey1, hpkePubKey1, [], undefined, undefined),
                new NodeData(hpkePrivKey2, hpkePubKey2, [], credentialB, undefined),
                new NodeData(hpkePrivKey3, hpkePubKey3, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey4, [], credentialC, undefined),
            ]),
            new Array(3),
        );
        const ratchetTreeView2v0 = new RatchetTreeView(
            x25519HkdfSha256Aes128Gcm, 2,
            new Tree<NodeData>([
                new NodeData(undefined, hpkePubKey0, [], credentialA, undefined),
                new NodeData(undefined, hpkePubKey1, [], undefined, undefined),
                new NodeData(undefined, hpkePubKey2, [], credentialB, undefined),
                new NodeData(hpkePrivKey3, hpkePubKey3, [], undefined, undefined),
                new NodeData(hpkePrivKey4, hpkePubKey4, [], credentialC, undefined),
            ]),
            new Array(3),
        );

        const [, hpkePubKey2v1] = await x25519HkdfSha256.generateKeyPair();
        const kpBv1 = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey2v1.serialize(),
            credentialB,
            [],
            signingPrivKeyB,
        );

        const [, hpkePubKey0v1] = await x25519HkdfSha256.generateKeyPair();
        const kpDv1 = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey0v1.serialize(),
            credentialD,
            [],
            signingPrivKeyD,
        );

        const [, hpkePubKey6v1] = await x25519HkdfSha256.generateKeyPair();
        const kpEv1 = await KeyPackage.create(
            ProtocolVersion.Mls10,
            CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
            await hpkePubKey6v1.serialize(),
            credentialE,
            [],
            signingPrivKeyE,
        );

        const ratchetTreeView2v1 = await ratchetTreeView2v0.applyProposals([
            new Remove(0),
            new Update(kpBv1),
            new Add(kpDv1),
            new Add(kpEv1),
        ]);

        const nodes = [...ratchetTreeView2v1.tree];

        // public keys from elliptic don't have the same internals after
        // serializing then deserializng, so we can't just compare the whole NodeData
        expect(await nodes[0].publicKey.serialize())
            .toEqual(await hpkePubKey0v1.serialize());
        expect(nodes[0].credential).toEqual(credentialD);
        expect(nodes[1]).toEqual(new NodeData(
            undefined,
            undefined,
            [nodes[2], nodes[0]],
            undefined,
            undefined,
        ));
        expect(await nodes[2].publicKey.serialize())
            .toEqual(await hpkePubKey2v1.serialize());
        expect(nodes[2].credential).toEqual(credentialB);
        expect(nodes[3]).toEqual(new NodeData(
            undefined,
            undefined,
            [nodes[2], nodes[0], nodes[6]],
            undefined,
            undefined,
        ));
        expect(nodes[4]).toEqual(new NodeData(
            hpkePrivKey4,
            hpkePubKey4,
            [],
            credentialC,
            undefined,
        ));
        expect(nodes[5]).toEqual(new NodeData(
            undefined,
            undefined,
            [nodes[6]],
            undefined,
            undefined,
        ));
        expect(await nodes[6].publicKey.serialize())
            .toEqual(await hpkePubKey6v1.serialize());
        expect(nodes[6].credential).toEqual(credentialE);
    });
});
