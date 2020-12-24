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

import {EMPTY_BYTE_ARRAY, NODE, PATH, ProposalType} from "./constants";
import {concatUint8Array, eqUint8Array} from "./util";
import {Leaf, Internal, Node, Tree} from "./lbbtree";
import * as treemath from "./treemath";
import {Extension, ParentNode, RatchetTree, KeyPackage} from "./keypackage";
import {KEMPrivateKey, KEMPublicKey} from "./hpke/base";
import {CipherSuite} from "./ciphersuite";
import {deriveSecret} from "./keyschedule";
import {Credential} from "./credential";
import {
    HPKECiphertext,
    MLSPlaintext,
    UpdatePathNode,
    UpdatePath,
    Add,
    Update,
    Remove,
    Proposal,
} from "./message";
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
        public unmergedLeaves: number[],
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
async function resolutionOf(
    node: Node<NodeData>,
    keyPackages: KeyPackage[],
    omitLeaves?: Set<number>,
): Promise<KEMPublicKey[]> {
    if (omitLeaves === undefined) {
        omitLeaves = new Set();
    }
    // FIXME: return empty if the node belongs to a leaf that should be omitted
    if (node.data !== undefined) {
        const ret = [node.data.publicKey];
        for (const leafNum of node.data.unmergedLeaves) {
            if (!omitLeaves.has(leafNum)) {
                ret.push(await keyPackages[leafNum].getHpkeKey());
            }
        }
        return ret;
    } else if (node instanceof Leaf) {
        return []
    } else {
        return (await resolutionOf(node.leftChild, keyPackages, omitLeaves))
            .concat(await resolutionOf(node.rightChild, keyPackages, omitLeaves));
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#views-of-a-ratchet-tree-views

type MakeKeyPackage = (pubKey: Uint8Array) => Promise<KeyPackage>;

export class RatchetTreeView {
    // NOTE: we assume that the identity in each credential is unique
    readonly idToLeafNum: Map<string, number>;
    readonly emptyLeaves: number[];
    readonly parentNodes: Record<number, [ParentNode, Uint8Array]>;
    readonly nodeHashes: Record<number, Uint8Array>;
    constructor(
        readonly cipherSuite: CipherSuite,
        readonly leafNum: number,
        readonly tree: Tree<NodeData>,
        readonly keyPackages: (KeyPackage | undefined)[],
        readonly groupContext: GroupContext,
        idToLeafNum?: Map<string, number>,
        emptyLeaves?: number[],
        parentNodes?: Record<number, [ParentNode, Uint8Array]>,
        nodeHashes?: Record<number, Uint8Array>,
    ) {
        this.idToLeafNum = idToLeafNum || new Map(
            [...tree]
                .filter((val, idx) => !(idx % 2))
                .map((val, idx): [string, number] => {
                    if (val.credential) {
                        // FIXME: do something better than toString?
                        return [val.credential.identity.toString(), idx];
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
        this.parentNodes = parentNodes || {};
        this.nodeHashes = nodeHashes || {};
    }

    async toRatchetTreeExtension(): Promise<RatchetTree> {
        const nodes: Array<KeyPackage | ParentNode | undefined> =
            new Array(this.tree.size * 2 - 1);

        const createNode = async (
            nodeNum: number, parentHash: Uint8Array, node: Node<NodeData>,
        ) => {
            const data = node.data;
            if (nodeNum & 0x1) { // internal node
                if (nodeNum in this.parentNodes) {
                    const [parentNode, newParentHash] = this.parentNodes[nodeNum];
                    nodes[nodeNum] = parentNode;
                    await Promise.all([
                        createNode(
                            treemath.left(nodeNum),
                            newParentHash, (node as Internal<NodeData>).leftChild,
                        ),
                        createNode(
                            treemath.right(nodeNum, this.tree.size),
                            newParentHash, (node as Internal<NodeData>).rightChild,
                        ),
                    ]);
                } else {
                    const parentNode = nodes[nodeNum] = new ParentNode(
                        data.publicKey ? await data.publicKey.serialize() : EMPTY_BYTE_ARRAY,
                        data.unmergedLeaves,
                        parentHash,
                    );
                    const newParentHash = await this.cipherSuite.hash.hash(
                        tlspl.encode([parentNode.encoder]),
                    );
                    this.parentNodes[nodeNum] = [parentNode, newParentHash];
                    await Promise.all([
                        createNode(
                            treemath.left(nodeNum),
                            newParentHash, (node as Internal<NodeData>).leftChild,
                        ),
                        createNode(
                            treemath.right(nodeNum, this.tree.size),
                            newParentHash, (node as Internal<NodeData>).rightChild,
                        ),
                    ]);
                }
            } else { // leaf node
                nodes[nodeNum] = this.keyPackages[nodeNum / 2];
            }
        }

        await createNode(treemath.root(this.tree.size), EMPTY_BYTE_ARRAY, this.tree.root);
        return new RatchetTree(nodes);
    }
    static async fromRatchetTreeExtension(
        cipherSuite: CipherSuite, ext: RatchetTree, keyPackage: KeyPackage, secretKey: KEMPrivateKey,
    ): Promise<RatchetTreeView> {
        const ourIdentity = keyPackage.credential.identity;
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
                // FIXME: check parent hash if such an extension exists
                keyPackages.push(node);
                if (eqUint8Array(node.credential.identity, ourIdentity)) {
                    leafNum = i / 2;
                }
                nodes[i] = new NodeData(
                    undefined,
                    await node.getHpkeKey(),
                    [],
                    node.credential,
                    undefined,
                );
                idToLeafNum.set(node.credential.identity.toString(), i / 2);
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
                if (node.publicKey.length === 0) {
                    nodes[i] = new NodeData(
                        undefined,
                        undefined,
                        node.unmergedLeaves,
                        undefined,
                        undefined,
                    );
                } else {
                    nodes[i] = new NodeData(
                        undefined,
                        await node.getHpkeKey(cipherSuite),
                        node.unmergedLeaves,
                        undefined,
                        undefined,
                    );
                }
            }
        }

        if (leafNum === undefined) {
            throw new Error("Could not find our leaf");
        }
        nodes[leafNum * 2].privateKey = secretKey;
        return new RatchetTreeView(
            cipherSuite,
            leafNum,
            new Tree(nodes),
            keyPackages,
            new GroupContext( // FIXME:
                new Uint8Array(),
                0,
                new Uint8Array(),
                new Uint8Array(),
                [],
            ),
            idToLeafNum,
            emptyLeaves,
        )
    }

    async update(makeKeyPackage: MakeKeyPackage):
    Promise<[UpdatePath, Uint8Array, RatchetTreeView]> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#ratchet-tree-evolution
        const copath = [...this.tree.coPathOfLeafNum(this.leafNum)].reverse();
        const n = copath.length;
        const keyPackages = Array.from(this.keyPackages); // FIXME: O(n)

        // FIXME: is this the right length?
        const leafSecret = new Uint8Array(this.cipherSuite.hpke.kem.privateKeyLength);
        window.crypto.getRandomValues(leafSecret);
        const [leafPriv, leafPub] = await this.cipherSuite.hpke.kem.deriveKeyPair(leafSecret);
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

        const context = tlspl.encode([this.groupContext.encoder]);
        for (let i = 0; i < n; i++) {
            // derive secrets for this node
            currPathSecret = await deriveSecret(this.cipherSuite, currPathSecret, PATH);
            const currNodeSecret = await deriveSecret(this.cipherSuite, currPathSecret, NODE);
            const [currNodePriv, currNodePub] = await this.cipherSuite.hpke.kem.deriveKeyPair(currNodeSecret);

            newPath.push(new NodeData(
                currNodePriv,
                currNodePub,
                [], // FIXME: ???
                undefined,
                undefined, // FIXME:
            ));

            const encryptedPathSecret: HPKECiphertext[] = [];
            // encrypt the path secret for users under the copath
            for (const publicKey of await resolutionOf(copath[i], this.keyPackages)) {
                // FIXME: "For each UpdatePathNode, the resolution of the
                // corresponding copath node MUST be filtered by removing all
                // new leaf nodes added as part of this MLS Commit message."
                encryptedPathSecret.push(await HPKECiphertext.encrypt(
                    this.cipherSuite.hpke,
                    publicKey,
                    context,
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
            await deriveSecret(this.cipherSuite, currPathSecret, PATH),
            new RatchetTreeView(
                this.cipherSuite,
                this.leafNum,
                newTree,
                keyPackages,
                this.groupContext, // FIXME:
            ),
        ];
    }

    async applyUpdatePath(fromNode: number, updatePath: UpdatePath):
    Promise<[Uint8Array, RatchetTreeView]> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#synchronizing-views-of-the-tree

        const keyPackages = Array.from(this.keyPackages); // FIXME: O(n)
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
            // know exactly which node was encrypted to which key.
            const encrKeyPairs: [HPKECiphertext, KEMPrivateKey][] =
                [].concat(...updatePathNode.encryptedPathSecret.map(
                    encr => privateKeys.map(key => [encr, key]),
                ));
            for (const [encryptedPathSecret, key] of encrKeyPairs) {
                try {
                    currPathSecret = await encryptedPathSecret.decrypt(
                        this.cipherSuite.hpke, key,
                        tlspl.encode([this.groupContext.encoder]),
                    );
                    break;
                } catch (e) {}
            }
            if (currPathSecret) {
                break;
            }
            newPath.push(new NodeData(
                undefined,
                await this.cipherSuite.hpke.kem.deserialize(updatePathNode.publicKey),
                [], // FIXME: ???
                undefined,
                undefined, // FIXME:
            ))
        }

        if (!currPathSecret) {
            throw new Error("Could not decrypt path secret");
        }

        for (; i < updatePath.nodes.length; i++) {
            const currNodeSecret = await deriveSecret(this.cipherSuite, currPathSecret, NODE);
            const [currNodePriv, currNodePub] = await this.cipherSuite.hpke.kem.deriveKeyPair(currNodeSecret);

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

            currPathSecret = await deriveSecret(this.cipherSuite, currPathSecret, PATH);
        }

        const newTree = this.tree.replacePathToLeaf(fromNode, newPath.reverse());

        return [
            currPathSecret,
            new RatchetTreeView(
                this.cipherSuite,
                this.leafNum,
                newTree,
                keyPackages,
                this.groupContext, // FIXME:
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
            idToLeafNum = new Map(idToLeafNum); // FIXME: O(n)
            emptyLeaves = Array.from(emptyLeaves); // FIXME: O(n)
            for (const remove of removes) {
                const path = [...tree.pathToLeafNum(remove.removed)];

                idToLeafNum.delete(path[path.length - 1].credential.identity.toString());
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
            const leafNum = this.idToLeafNum.get(update.keyPackage.credential.identity.toString());
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
                            data.unmergedLeaves.concat([leafNum]), // FIXME: ???
                            undefined,
                            undefined, // FIXME:
                        );
                    }
                });
            tree = tree.replacePathToLeaf(leafNum, path);
        }

        if (adds.length) {
            if (!removes.length) {
                idToLeafNum = new Map(idToLeafNum); // FIXME: O(n)
                emptyLeaves = Array.from(emptyLeaves); // FIXME: O(n)
            }
            emptyLeaves.sort(); // FIXME: O(n log n)
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
                                    data.unmergedLeaves.concat([leafNum]), // FIXME: ???
                                    undefined,
                                    undefined, // FIXME:
                                );
                            }
                        });
                    tree = tree.replacePathToLeaf(leafNum, path);
                    idToLeafNum.set(add.keyPackage.credential.identity.toString(), leafNum);
                } else {
                    const leafNum = tree.size;
                    keyPackages[leafNum] = add.keyPackage;
                    tree = tree.addNode(
                        leafData,
                        (leftChild, rightChild) => {
                            return new NodeData(
                                undefined,
                                undefined,
                                leftChild.data.unmergedLeaves.concat([leafNum]), // FIXME: ???
                                undefined,
                                undefined, // FIXME:
                            );
                        },
                    );
                    idToLeafNum.set(add.keyPackage.credential.identity.toString(), leafNum);
                }
            }
        }

        return new RatchetTreeView(
            this.cipherSuite,
            this.leafNum,
            tree,
            keyPackages,
            this.groupContext, // FIXME:
            idToLeafNum,
            emptyLeaves,
        );
    }

    // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#parent-hash
    async calculateParentHashForLeaf(leafNum: number): Promise<Uint8Array> {
        const path = [...this.tree.pathToLeafNum(leafNum)];
        path.pop(); // stop before the KeyPackage
        let parentHash = EMPTY_BYTE_ARRAY; // parentHash for root is the empty string

        for (const node of path) {
            const parentNode = new ParentNode(
                node.publicKey ? await node.publicKey.serialize() : EMPTY_BYTE_ARRAY,
                node.unmergedLeaves,
                parentHash,
            );
            const encoding = tlspl.encode([parentNode.encoder]);
            parentHash = await this.cipherSuite.hash.hash(encoding);
        }

        return parentHash;
    }

    // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#tree-hashes
    async calculateTreeHash(): Promise<Uint8Array> {
        // the ratchet tree extension gives us ParentNode structs
        const ratchetTree = await this.toRatchetTreeExtension();
        const nodes = ratchetTree.nodes;

        const calculateNodeHash = async (
            nodeNum: number, node: Node<NodeData>,
        ): Promise<Uint8Array> => {
            if (!(nodeNum in this.nodeHashes)) {
                if (nodeNum & 0x1) { // internal node
                    this.nodeHashes[nodeNum] = tlspl.encode([
                        tlspl.uint32(nodeNum),
                        nodes[nodeNum] && ((nodes[nodeNum] as ParentNode).publicKey.length > 0) ?
                            tlspl.struct([tlspl.uint8(1), (nodes[nodeNum] as ParentNode).encoder]) :
                            tlspl.uint8(0),
                        tlspl.variableOpaque(
                            await calculateNodeHash(
                                treemath.left(nodeNum),
                                (node as Internal<NodeData>).leftChild,
                            ),
                            1,
                        ),
                        tlspl.variableOpaque(
                            await calculateNodeHash(
                                treemath.right(nodeNum, this.tree.size),
                                (node as Internal<NodeData>).rightChild,
                            ),
                            1,
                        ),
                    ]); // ParentNodeHashInput struct
                } else { // leaf node
                    this.nodeHashes[nodeNum] = tlspl.encode([
                        tlspl.uint32(nodeNum),
                        nodes[nodeNum] ?
                            tlspl.struct([tlspl.uint8(1), (nodes[nodeNum] as KeyPackage).encoder]) :
                            tlspl.uint8(0),
                    ]); // LeafNodeHashInput struct
                }
            }
            return this.nodeHashes[nodeNum];
        }

        return await calculateNodeHash(treemath.root(this.tree.size), this.tree.root);
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
): Promise<[Uint8Array, Uint8Array]> {
    const mlsPlaintextCommitContent = tlspl.encode([plaintext.commitContentEncoder]);
    const confirmedTranscriptHash = await cipherSuite.hash.hash(
        concatUint8Array([interimTranscriptHash, mlsPlaintextCommitContent]),
    );
    const newInterimTranscriptHash = await cipherSuite.hash.hash(
        concatUint8Array([confirmedTranscriptHash, plaintext.confirmationTag]),
    );
    return [confirmedTranscriptHash, newInterimTranscriptHash];
}
