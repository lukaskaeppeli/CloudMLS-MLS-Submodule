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

import {Secrets, generateSecrets, generateSecretsFromJoinerSecret} from "./keyschedule";
import {NodeData, RatchetTreeView} from "./ratchettree";
import {Extension, KeyPackage, RatchetTree} from "./keypackage";
import {CipherSuite} from "./ciphersuite";
import {KEMPrivateKey} from "./hpke/base";
import {SigningPrivateKey} from "./signatures";
import {Tree} from "./lbbtree";
import {MLSPlaintext, Add, Commit, ProposalWrapper, Sender} from "./message";
import {concatUint8Array, eqUint8Array} from "./util";
import {EMPTY_BYTE_ARRAY, ProtocolVersion, SenderType} from "./constants";
import {Credential} from "./credential";
import {GroupInfo, Welcome} from "./welcome";
import * as tlspl from "./tlspl";

/* Manages the state of the group.
 */

export class Group {
    constructor(
        readonly version: ProtocolVersion,
        readonly cipherSuite: CipherSuite,
        readonly groupId: Uint8Array,
        public epoch: number,
        readonly extensions: Extension[],
        private hpkeKey: KEMPrivateKey,
        public confirmedTranscriptHash: Uint8Array,
        public interimTranscriptHash: Uint8Array,
        public ratchetTreeView: RatchetTreeView,
        private secrets: Secrets,
    ) {}

    /** Create a brand new group.
     */
    static async createNew(
        version: ProtocolVersion,
        cipherSuite: CipherSuite,
        groupId: Uint8Array,
        credential: Credential,
        signingPrivateKey: SigningPrivateKey,
        otherMembers: KeyPackage[],
        // FIXME: PSK?
    ): Promise<[Group, MLSPlaintext, Welcome]> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#group-creation
        const groupExtensions = []; // FIXME: pass as parameter?
        const [hpkePrivateKey, hpkePubKey] = await cipherSuite.hpke.kem.generateKeyPair();
        const keyPackage = await KeyPackage.create(
            version,
            cipherSuite,
            await hpkePubKey.serialize(),
            credential,
            [], // FIXME: extensions -- same as group extensions?
            signingPrivateKey,
        );

        const ratchetTreeView0 = new RatchetTreeView(
            cipherSuite,
            0,
            new Tree<NodeData>([
                new NodeData(undefined, hpkePubKey, [], credential, undefined, 0),
            ]),
            [keyPackage],
        );

        const initialGroupContext = new GroupContext(
            groupId,
            0,
            await ratchetTreeView0.calculateTreeHash(),
            EMPTY_BYTE_ARRAY,
            groupExtensions,
        );

        const adds = otherMembers.map(keyPackage => new Add(keyPackage));

        const ratchetTreeView1 = await ratchetTreeView0.applyProposals(adds);

        const provisionalGroupContext = new GroupContext(
            groupId,
            0,
            await ratchetTreeView1.calculateTreeHash(),
            EMPTY_BYTE_ARRAY,
            groupExtensions,
        );

        const [updatePath, pathSecrets, ratchetTreeView2] = await ratchetTreeView1.update(
            (pubkey) => KeyPackage.create(
                version,
                cipherSuite,
                pubkey,
                credential,
                [], // FIXME: extensions -- same as group extension?
                signingPrivateKey,
            ),
            provisionalGroupContext,
        );

        // FIXME: if we have too many adds, we may need to send the adds as
        // separate proposals, and the Commit message will need to use hashes
        // instead
        const commit = new Commit(adds.map(add => new ProposalWrapper(add)), updatePath);
        // FIXME: Construct an MLSPlaintext object containing the Commit
        // object. Sign the MLSPlaintext using the current epoch's GroupContext
        // as context. Use the signature, the commit_secret and the psk_secret
        // to advance the key schedule and compute the confirmation_tag value
        // in the MLSPlaintext. ???
        const plaintext = await MLSPlaintext.create(
            cipherSuite,
            groupId, 0,
            new Sender(SenderType.Member, 0),
            EMPTY_BYTE_ARRAY,
            commit,
            signingPrivateKey,
            initialGroupContext,
        );

        const confirmedTranscriptHash =
            await calculateConfirmedTranscriptHash(
                cipherSuite,
                plaintext,
                EMPTY_BYTE_ARRAY, // initial interim transcript hash
            );

        const newGroupContext = new GroupContext(
            groupId,
            1,
            await ratchetTreeView2.calculateTreeHash(),
            confirmedTranscriptHash,
            groupExtensions,
        );

        const initSecret = new Uint8Array(cipherSuite.hpke.kdf.extractLength);
        window.crypto.getRandomValues(initSecret);
        const commitSecret = pathSecrets[pathSecrets.length - 1];
        const secrets =
            await generateSecrets(
                cipherSuite,
                initSecret,
                commitSecret,
                newGroupContext,
            );

        await plaintext.calculateTags(
            cipherSuite,
            secrets.confirmationKey,
            EMPTY_BYTE_ARRAY, // FIXME: ???
            initialGroupContext,
        );

        const interimTranscriptHash =
            await calculateInterimTranscriptHash(
                cipherSuite,
                plaintext,
                confirmedTranscriptHash,
            );

        const group = new Group(
            version,
            cipherSuite,
            groupId,
            1,
            groupExtensions,
            hpkePrivateKey,
            confirmedTranscriptHash,
            interimTranscriptHash,
            ratchetTreeView2,
            secrets,
        );

        // make welcome messages
        /* we are leaf 0.  Our parent will be the lowest common ancestor (LCA)
         * for the next leaf.  Our grandparent will be the lowest common
         * ancestor for the next 2 leaves.  Our great-grandparent will be the
         * lowest common ancestor for the next 4 leaves, etc.
         *
         *                                             D
         *                         ___________________/ \
         *                        /                      \
         *                       C                        \
         *             _________/ \_________               \
         *            /                     \               \
         *           B                       *               \
         *       ___/ \___               ___/ \___            \
         *      /         \             /         \            |
         *     A           *           *           *           *
         *    / \         / \         / \         / \         / \
         *   /   \       /   \       /   \       /   \       /   \
         *  0     1     2     3     4     5     6     7     8     9
         *      \_ _/  \___ ___/   \_________ __________/  \_______ ...
         *        V        V                 V                     V
         *    LCA is A  LCA is B         LCA is C             LCA is D  ...
         *
         * So we iterate over the path secrets array and encrypt each secret
         * for the next 2^i leaves.
         */
        const recipients: {keyPackage: KeyPackage, pathSecret: Uint8Array}[] = [];
        for (let i = 0; 1 << i < otherMembers.length; i++) {
            const numRecipients = 1 << i;
            const maxRecipients = otherMembers.length - numRecipients + 1;
            for (let j = 0; j < numRecipients && j < maxRecipients; j++) {
                recipients.push({
                    keyPackage: otherMembers[numRecipients - 1 + j],
                    pathSecret: pathSecrets[i],
                });
            }
        }
        const groupInfo = await GroupInfo.create(
            groupId,
            1,
            await ratchetTreeView2.calculateTreeHash(),
            confirmedTranscriptHash,
            // FIXME: other extensions?
            // FIXME: allow sending the ratchet tree in other ways
            [await ratchetTreeView2.toRatchetTreeExtension()],
            plaintext.confirmationTag,
            0,
            signingPrivateKey,
        );
        const welcome = await Welcome.create(
            cipherSuite,
            secrets.joinerSecret,
            groupInfo,
            recipients,
        );

        return [group, plaintext, welcome];
    }

    static async createFromWelcome(
        welcome: Welcome,
        keyPackages: Record<string, [KeyPackage, KEMPrivateKey]>,
    ): Promise<[string, Group]> {
        const cipherSuite = welcome.cipherSuite;

        const [groupSecrets, groupInfo, keyId] = await welcome.decrypt(keyPackages);
        // FIXME: check signature on groupInfo (we need a public signing key)

        // FIXME: support other methods of getting the ratchet tree
        const [keyPackage, hpkeKey] = keyPackages[keyId];
        const ratchetTreeExt = groupInfo.extensions.find(
            ext => ext instanceof RatchetTree,
        ) as RatchetTree | undefined;
        if (!ratchetTreeExt) {
            throw new Error("Could not find ratchet tree");
        }

        const [ratchetTreeView, commitSecret] =
            await RatchetTreeView.fromRatchetTreeExtension(
                cipherSuite,
                ratchetTreeExt,
                keyPackage,
                hpkeKey,
                groupInfo.signerIndex,
                groupSecrets.pathSecret,
            );
        const signerKeyPackage = ratchetTreeView.keyPackages[groupInfo.signerIndex];
        if (!signerKeyPackage) {
            throw new Error("Signer doesn't have a key package");
        }
        if (!await groupInfo.checkSignature(signerKeyPackage.credential)) {
            throw new Error("Signature on group info does not match");
        }

        const treeHash = await ratchetTreeView.calculateTreeHash();
        if (!eqUint8Array(treeHash, groupInfo.treeHash)) {
            throw new Error("Tree hash does not match");
        }

        // FIXME: For each non-empty parent node, verify that exactly one of
        // the node's children are non-empty and have the hash of this node set
        // as their parent_hash value (if the child is another parent) or has a
        // parent_hash extension in the KeyPackage containing the same value
        // (if the child is a leaf). If either of the node's children is empty,
        // and in particular does not have a parent hash, then its respective
        // children's parent_hash values have to be considered instead.

        // check the signature on all the key packages
        // FIXME: this doesn't work??
        /*
        await Promise.all(
            ratchetTreeView.keyPackages.map(async (keyPackage, idx) => {
                if (keyPackage !== undefined && !(await keyPackage.checkSignature())) {
                    console.log(keyPackage);
                    throw new Error(`Invalid signature for key package #${idx}`);
                }
            }),
        );
        */

        const groupContext = new GroupContext(
            groupInfo.groupId,
            groupInfo.epoch,
            groupInfo.treeHash,
            groupInfo.confirmedTranscriptHash,
            [], // FIXME: extensions -- same as groupInfo.extensions minus ratchettree?
        );

        const secrets = await generateSecretsFromJoinerSecret(
            cipherSuite,
            groupSecrets.joinerSecret,
            commitSecret,
            groupContext,
        );

        const interimTranscriptHash = await calculateInterimTranscriptHash(
            cipherSuite,
            groupInfo,
            groupInfo.confirmedTranscriptHash,
        );

        const group = new Group(
            keyPackage.version, // FIXME: is this correct?
            cipherSuite,
            groupInfo.groupId,
            groupInfo.epoch,
            [], // FIXME: extensions -- same as groupInfo.extensions minus ratchettree?
            hpkeKey,
            groupInfo.confirmedTranscriptHash,
            interimTranscriptHash,
            ratchetTreeView,
            secrets,
        );

        return [keyId, group];
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#group-state

export class GroupContext {
    constructor(
        readonly groupId: Uint8Array,
        readonly epoch: number,
        readonly treeHash: Uint8Array,
        readonly confirmedTranscriptHash: Uint8Array,
        readonly extensions: Extension[],
    ) {}

    static decode(buffer: Uint8Array, offset: number): [GroupContext, number] {
        const [
            [groupId, epoch, treeHash, confirmedTranscriptHash, extensions],
            offset1,
        ] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeUint64,
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeVector(Extension.decode, 4),
            ],
            buffer, offset,
        );
        return [
            new GroupContext(groupId, epoch, treeHash, confirmedTranscriptHash, extensions),
            offset1,
        ]
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint64(this.epoch),
            tlspl.variableOpaque(this.treeHash, 1),
            tlspl.variableOpaque(this.confirmedTranscriptHash, 1),
            tlspl.vector(this.extensions.map(x => x.encoder), 4),
        ]);
    }
}

export async function calculateConfirmedTranscriptHash(
    cipherSuite: CipherSuite,
    plaintext: MLSPlaintext,
    interimTranscriptHash: Uint8Array,
): Promise<Uint8Array> {
    const mlsPlaintextCommitContent = tlspl.encode([plaintext.commitContentEncoder]);
    const confirmedTranscriptHash = await cipherSuite.hash.hash(
        concatUint8Array([interimTranscriptHash, mlsPlaintextCommitContent]),
    );
    return confirmedTranscriptHash;
}

export async function calculateInterimTranscriptHash(
    cipherSuite: CipherSuite,
    plaintext: {confirmationTag?: Uint8Array},
    confirmedTranscriptHash: Uint8Array,
): Promise<Uint8Array> {
    const newInterimTranscriptHash = await cipherSuite.hash.hash(
        concatUint8Array([confirmedTranscriptHash, plaintext.confirmationTag]),
    );
    return newInterimTranscriptHash;
}