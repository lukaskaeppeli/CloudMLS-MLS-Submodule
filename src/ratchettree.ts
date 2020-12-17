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

import {EMPTY_BYTE_ARRAY, NODE, PATH, CipherSuite, ProposalType} from "./constants";
import {eqUint8Array} from "./util";
import {Leaf, Node, Tree} from "./lbbtree";
import {Extension, ParentNode, RatchetTree, KeyPackage} from "./keypackage";
import {KEMPrivateKey, KEMPublicKey, HPKE} from "./hpke/base";
import {deriveSecret} from "./keyschedule";
import {Credential} from "./credential";
import {HPKECiphertext, UpdatePathNode, UpdatePath, Add, Update, Remove, Proposal} from "./message";
import * as tlspl from "./tlspl";

/** The ratchet tree allows group members to efficiently update the group secrets.
 */

// Ratchet Tree Nodes
// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#ratchet-tree-nodes

/* Each node in a ratchet tree contains up to five values:
 *
 * - A private key (only within the member's direct path, see below)
 * - A public key
 * - An ordered list of leaf indices for "unmerged" leaves (see {{views}})
 * - A credential (only for leaf nodes)
 * - A hash of the node's parent, as of the last time the node was changed.
 */

export class NodeData {
    constructor(
        public privateKey: KEMPrivateKey | undefined,
        public publicKey: KEMPublicKey | undefined,
        public unmergedLeaves: NodeData[],
        public credential: Credential | undefined,
        public parentHash: Uint8Array | undefined,
    ) {}
}

/* The resolution of a node is an ordered list of non-blank nodes that
 * collectively cover all non-blank descendants of the node.
 *
 * - The resolution of a non-blank node comprises the node itself, followed by
 *   its list of unmerged leaves, if any
 * - The resolution of a blank leaf node is the empty list
 * - The resolution of a blank intermediate node is the result of concatenating
 *   the resolution of its left child with the resolution of its right child,
 *   in that order
 */
function resolutionOf(node: Node<NodeData>): NodeData[] {
    if (node.data !== undefined) {
        return [node.data].concat(node.data.unmergedLeaves);
    } else if (node instanceof Leaf) {
        return []
    } else {
        return resolutionOf(node.leftChild).concat(resolutionOf(node.rightChild));
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#views-of-a-ratchet-tree-views

type MakeKeyPackage = (pubKey: Uint8Array) => Promise<KeyPackage>;

export class RatchetTreeView {
    // NOTE: we assume that the identity in each credential is unique
    readonly idToLeafNum: Map<string, number>;
    readonly emptyLeaves: number[];
    constructor(
        readonly hpke: HPKE,
        readonly leafNum: number,
        readonly tree: Tree<NodeData>,
        readonly keyPackages: (KeyPackage | undefined)[],
        idToLeafNum?: Map<string, number>,
        emptyLeaves?: number[],
    ) {
        this.idToLeafNum = idToLeafNum || new Map(
            [...tree]
                .filter((val, idx) => !(idx % 2))
                .map((val, idx): [string, number] => {
                    if (val.credential) {
                        // FIXME: do something better than toString?
                        return [val.credential.credential.identity.toString(), idx];
                    } else {
                        return undefined;
                    }
                })
                .filter(val => val !== undefined),
        );
        this.emptyLeaves = emptyLeaves ||
            [...tree]
                .filter((val, idx) => !(idx % 0))
                .map((val, idx): [NodeData, number] => [val, idx])
                .filter(v => v[0].publicKey === undefined)
                .map(v => v[1]);
    }

    async toRatchetTreeExtension(): Promise<RatchetTree> {
        const treeNodes: NodeData[] = [...this.tree];
        const nodes: Array<KeyPackage | ParentNode | undefined> =
            await Promise.all(treeNodes.map(async (treeNode, i) => {
                if (treeNode.publicKey) {
                    if (i & 0x1) {
                        return new ParentNode(
                            await treeNode.publicKey.serialize(),
                            treeNode.unmergedLeaves.map((data: NodeData) => {
                                const identity = data.credential.credential.identity.toString();
                                return this.idToLeafNum.get(identity);
                            }),
                            new Uint8Array(), // FIXME: parentHash
                        );
                    } else {
                        return this.keyPackages[i / 2];
                    }
                } else {
                    return undefined;
                }
            }));
        return new RatchetTree(nodes);
    }
    static async fromRatchetTreeExtension(
        hpke: HPKE, ext: RatchetTree, keyPackage: KeyPackage, secretKey: KEMPrivateKey,
    ): Promise<RatchetTreeView> {
        const ourIdentity = keyPackage.credential.credential.identity;
        let leafNum: number | undefined = undefined;
        const nodes: NodeData[] = new Array(ext.nodes.length);
        const keyPackages: (KeyPackage | undefined)[] = [];
        const idToLeafNum: Map<string, number> = new Map();
        const emptyLeaves: number[] = [];

        // first process the leaf nodes (which are even-numbered)
        for (let i = 0; i < ext.nodes.length; i += 2) {
            const node = ext.nodes[i];
            if (node === undefined) {
                nodes[i] = new NodeData(undefined, undefined, [], undefined, undefined);
                keyPackages.push(undefined);
                emptyLeaves.push(i / 2);
            } else {
                if (!(node instanceof KeyPackage)) {
                    throw new Error(`Expected a key package at position ${i}`);
                }
                keyPackages.push(node);
                if (eqUint8Array(node.credential.credential.identity, ourIdentity)) {
                    leafNum = i / 2;
                }
                nodes[i] = new NodeData(
                    undefined,
                    await node.getHpkeKey(),
                    [],
                    node.credential,
                    undefined,
                );
                idToLeafNum.set(node.credential.credential.identity.toString(), i / 2);
            }
        }
        // next process the internal nodes
        for (let i = 1; i < ext.nodes.length; i += 2) {
            const node = ext.nodes[i];
            if (node === undefined) {
                nodes[i] = new NodeData(undefined, undefined, [], undefined, undefined);
            } else {
                if (!(node instanceof ParentNode)) {
                    throw new Error(`Expected a parent node at position ${i}`);
                }
                // FIXME: check parentHash
                nodes[i] = new NodeData(
                    undefined,
                    await node.getHpkeKey(CipherSuite.MLS10_128_DHKEMX25519_AES128GCM_SHA256_Ed25519),
                    node.unmergedLeaves.map(leafNum => nodes[leafNum * 2]),
                    undefined,
                    undefined,
                );
            }
        }

        if (leafNum === undefined) {
            throw new Error("Could not find our leaf");
        }
        nodes[leafNum * 2].privateKey = secretKey;
        return new RatchetTreeView(
            hpke,
            leafNum,
            new Tree(nodes),
            keyPackages,
            idToLeafNum,
            emptyLeaves,
        )
    }

    async update(makeKeyPackage: MakeKeyPackage):
    Promise<[UpdatePath, Uint8Array, RatchetTreeView]> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#ratchet-tree-evolution
        const copath = [...this.tree.coPathOfLeafNum(this.leafNum)].reverse();
        const n = copath.length;
        const keyPackages = Array.from(this.keyPackages);

        // FIXME: is this the right length?
        const leafSecret = new Uint8Array(this.hpke.kem.privateKeyLength);
        window.crypto.getRandomValues(leafSecret);
        const [leafPriv, leafPub] = await this.hpke.kem.deriveKeyPair(leafSecret);
        const newPath: NodeData[] = [new NodeData(
            leafPriv,
            leafPub,
            [],
            undefined, // FIXME:
            undefined, // FIXME:
        )];

        const keyPackage = await makeKeyPackage(await leafPub.serialize());
        keyPackages[this.leafNum] = keyPackage;
        const updatePathNodes: UpdatePathNode[] = [];

        let currPathSecret: Uint8Array = leafSecret;

        for (let i = 0; i < n; i++) {
            // derive secrets for this node
            currPathSecret = await deriveSecret(this.hpke, currPathSecret, PATH);
            const currNodeSecret = await deriveSecret(this.hpke, currPathSecret, NODE);
            const [currNodePriv, currNodePub] = await this.hpke.kem.deriveKeyPair(currNodeSecret);

            newPath.push(new NodeData(
                currNodePriv,
                currNodePub,
                [], // FIXME: ???
                undefined,
                undefined, // FIXME:
            ));

            const encryptedPathSecret: HPKECiphertext[] = [];
            // encrypt the path secret for users under the copath
            for (const nodeData of resolutionOf(copath[i])) {
                // FIXME: "For each UpdatePathNode, the resolution of the
                // corresponding copath node MUST be filtered by removing all
                // new leaf nodes added as part of this MLS Commit message."
                encryptedPathSecret.push(await HPKECiphertext.encrypt(
                    this.hpke,
                    nodeData.publicKey,
                    EMPTY_BYTE_ARRAY, // FIXME: group context,
                    currPathSecret,
                ));
            }
            updatePathNodes.push(new UpdatePathNode(
                await currNodePub.serialize(),
                encryptedPathSecret,
            ));
        }

        leafSecret.fill(0);

        // generate UpdatePath message
        const updatePath = new UpdatePath(keyPackage, updatePathNodes);

        // update our tree
        const newTree = this.tree.replacePathToLeaf(this.leafNum, newPath.reverse());

        return [
            updatePath,
            await deriveSecret(this.hpke, currPathSecret, PATH),
            new RatchetTreeView(this.hpke, this.leafNum, newTree, keyPackages),
        ];
    }

    async applyUpdatePath(fromNode: number, updatePath: UpdatePath):
    Promise<[Uint8Array, RatchetTreeView]> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#synchronizing-views-of-the-tree

        const keyPackages = Array.from(this.keyPackages);
        const privateKeys =
            [...this.tree.pathToLeafNum(this.leafNum)]
                .map(data => data.privateKey)
                .filter(data => data !== undefined);

        // FIXME: check that updatePath.leafKeyPackage.credential matches the
        // credential we already have for the node
        if (!await updatePath.leafKeyPackage.checkSignature()) {
            throw new Error("Bad signature on key package");
        }

        keyPackages[fromNode] = updatePath.leafKeyPackage;

        const newPath = [new NodeData(
            undefined,
            await updatePath.leafKeyPackage.getHpkeKey(),
            [],
            updatePath.leafKeyPackage.credential,
            undefined, // FIXME:
        )];

        let currPathSecret: Uint8Array;
        let i = 0;
        for (; i < updatePath.nodes.length; i++) {
            const updatePathNode = updatePath.nodes[i];
            // FIXME: is there a better way of doing this than trying to
            // decrypt every ciphertext with every key?  In theory, we should
            // know exactly which ciphertext was encrypted to which key.  We
            // should also know which node will be encrypted for us.
            const encrKeyPairs: [HPKECiphertext, KEMPrivateKey][] =
                [].concat(...updatePathNode.encryptedPathSecret.map(
                    encr => privateKeys.map(key => [encr, key]),
                ));
            for (const [encryptedPathSecret, key] of encrKeyPairs) {
                try {
                    currPathSecret = await encryptedPathSecret.decrypt(
                        this.hpke, key,
                        EMPTY_BYTE_ARRAY, // FIXME: group context,
                    );
                    break;
                } catch (e) {}
            }
            if (currPathSecret) {
                break;
            }
            newPath.push(new NodeData(
                undefined,
                await this.hpke.kem.deserialize(updatePathNode.publicKey),
                [], // FIXME: ???
                undefined,
                undefined, // FIXME:
            ))
        }

        if (!currPathSecret) {
            throw new Error("Could not decrypt path secret");
        }

        for (; i < updatePath.nodes.length; i++) {
            const currNodeSecret = await deriveSecret(this.hpke, currPathSecret, NODE);
            const [currNodePriv, currNodePub] = await this.hpke.kem.deriveKeyPair(currNodeSecret);

            const serializedPubKey = await currNodePub.serialize();
            if (!eqUint8Array(serializedPubKey, updatePath.nodes[i].publicKey)) {
                throw new Error("Derived public key does not match");
            }

            newPath.push(new NodeData(
                currNodePriv,
                currNodePub,
                [], // FIXME: ???
                undefined,
                undefined, // FIXME:
            ));

            currPathSecret = await deriveSecret(this.hpke, currPathSecret, PATH);
        }

        const newTree = this.tree.replacePathToLeaf(fromNode, newPath.reverse());

        return [
            currPathSecret,
            new RatchetTreeView(
                this.hpke,
                this.leafNum,
                newTree,
                keyPackages,
                this.idToLeafNum,
                this.emptyLeaves,
            ),
        ];
    }

    async applyProposals(proposals: Proposal[]): Promise<RatchetTreeView> {
        let tree = this.tree;
        // removes are applied first, then updates, then adds
        const adds: Add[] = [];
        const updates: Update[] = [];
        const removes: Remove[] = [];
        let idToLeafNum = this.idToLeafNum;
        let emptyLeaves = this.emptyLeaves;
        const keyPackages = Array.from(this.keyPackages);

        for (const proposal of proposals) {
            switch (proposal.msgType) {
                case ProposalType.Add:
                    adds.push(proposal as Add);
                    break;
                case ProposalType.Update:
                    updates.push(proposal as Update);
                    break;
                case ProposalType.Remove:
                    removes.push(proposal as Remove);
                    break;
                default:
                    throw new Error("Unknown proposal type");
            }
        }

        if (removes.length) {
            idToLeafNum = new Map(idToLeafNum);
            emptyLeaves = Array.from(emptyLeaves);
            for (const remove of removes) {
                const path = [...tree.pathToLeafNum(remove.removed)];

                idToLeafNum.delete(path[path.length - 1].credential.credential.identity.toString());
                emptyLeaves.push(remove.removed);
                keyPackages[remove.removed] = undefined;

                const newPath =
                    path.map((data) => {
                        return new NodeData(
                            undefined,
                            undefined,
                            data.unmergedLeaves, // FIXME: ???
                            undefined,
                            undefined, // FIXME:
                        );
                    });
                tree = tree.replacePathToLeaf(remove.removed, newPath);
            }
        }

        for (const update of updates) {
            const leafNum = this.idToLeafNum.get(update.keyPackage.credential.credential.identity.toString());
            // FIXME: make sure the update's credential matches the credential
            // we already have
            keyPackages[leafNum] = update.keyPackage;
            const publicKey = await update.keyPackage.getHpkeKey();
            const leafData = new NodeData(
                leafNum === this.leafNum ? update.privateKey : undefined,
                publicKey,
                [],
                update.keyPackage.credential,
                undefined, // FIXME:
            );
            const path = [...tree.pathToLeafNum(leafNum)]
                .map((data, idx, arr) => {
                    if (idx === arr.length - 1) {
                        return leafData;
                    } else {
                        return new NodeData(
                            undefined,
                            undefined,
                            data.unmergedLeaves.concat([leafData]), // FIXME: ???
                            undefined,
                            undefined, // FIXME:
                        );
                    }
                });
            tree = tree.replacePathToLeaf(leafNum, path);
        }

        if (adds.length) {
            if (!removes.length) {
                idToLeafNum = new Map(idToLeafNum);
                emptyLeaves = Array.from(emptyLeaves);
            }
            emptyLeaves.sort();
            for (const add of adds) {
                const publicKey = await add.keyPackage.getHpkeKey();
                const leafData = new NodeData(
                    undefined,
                    publicKey,
                    [],
                    add.keyPackage.credential,
                    undefined, // FIXME:
                );
                if (emptyLeaves.length) {
                    const leafNum = emptyLeaves.shift();
                    keyPackages[leafNum] = add.keyPackage;
                    const path = [...tree.pathToLeafNum(leafNum)]
                        .map((data, idx, arr) => {
                            if (idx === arr.length - 1) {
                                return leafData;
                            } else {
                                return new NodeData(
                                    undefined,
                                    undefined,
                                    data.unmergedLeaves.concat([leafData]), // FIXME: ???
                                    undefined,
                                    undefined, // FIXME:
                                );
                            }
                        });
                    tree = tree.replacePathToLeaf(leafNum, path);
                    idToLeafNum.set(add.keyPackage.credential.credential.identity.toString(), leafNum);
                } else {
                    const leafNum = tree.size;
                    keyPackages[leafNum] = add.keyPackage;
                    tree = tree.addNode(
                        leafData,
                        (leftChild, rightChild) => {
                            return new NodeData(
                                undefined,
                                undefined,
                                leftChild.data.unmergedLeaves.concat([leafData]), // FIXME: ???
                                undefined,
                                undefined, // FIXME:
                            );
                        },
                    );
                    idToLeafNum.set(add.keyPackage.credential.credential.identity.toString(), leafNum);
                }
            }
        }


        return new RatchetTreeView(
            this.hpke,
            this.leafNum,
            tree,
            keyPackages,
            idToLeafNum,
            emptyLeaves,
        );
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

// FIXME: add function to calculate confirmed transcript hash
