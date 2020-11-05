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

import {EMPTY_BYTE_ARRAY, NODE, PATH} from "./constants";
import {Leaf, Internal, Node, Tree} from "./lbbtree";
import {KeyPackage} from "./keypackage";
import {KEMPrivateKey, KEMPublicKey, HPKE} from "./hpke/base";
import {deriveSecret} from "./keyschedule";
import {Credential} from "./credential";
import {HPKECiphertext, UpdatePathNode, UpdatePath} from "./message";
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
        public privateKey: KEMPrivateKey,
        public publicKey: KEMPublicKey,
        public unmergedLeaves: NodeData[],
        public credential: Credential,
        public parentHash: Uint8Array,
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
    constructor(
        readonly hpke: HPKE,
        readonly nodeNum: number,
        readonly tree: Tree<NodeData>,
    ) {}

    async update(makeKeyPackage: MakeKeyPackage): Promise<[UpdatePath, RatchetTreeView]> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#ratchet-tree-evolution
        const copath = [...this.tree.coPathOfLeafNum(this.nodeNum)].reverse();
        const n = copath.length;

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

            // encrypt the path secret for users under the copath
            for (const nodeData of resolutionOf(copath[i])) {
                // FIXME: "For each UpdatePathNode, the resolution of the
                // corresponding copath node MUST be filtered by removing all
                // new leaf nodes added as part of this MLS Commit message."
                updatePathNodes.push(new UpdatePathNode(
                    await nodeData.publicKey.serialize(),
                    await HPKECiphertext.encrypt(
                        this.hpke,
                        nodeData.publicKey,
                        EMPTY_BYTE_ARRAY, // FIXME: group context,
                        currPathSecret,
                    ),
                ));
            }
        }

        leafSecret.fill(0);

        // generate UpdatePath message
        const updatePath = new UpdatePath(keyPackage, updatePathNodes);

        // update our tree
        const newTree = this.tree.replacePathToLeaf(this.nodeNum, newPath.reverse());

        return [updatePath, new RatchetTreeView(this.hpke, this.nodeNum, newTree)];
    }

    async applyUpdatePath(fromNode: number, updatePath: UpdatePath): Promise<RatchetTreeView> {
        // https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#synchronizing-views-of-the-tree

        const privateKeys =
            [...this.tree.pathToLeafNum(this.nodeNum)]
                .map(data => data.privateKey)
                .filter(data => data !== undefined);

        // FIXME: check that updatePath.leafKeyPackage.credential matches the
        // credential we already have for the node
        if (!await updatePath.leafKeyPackage.checkSignature()) {
            throw new Error("Bad signature on key package");
        }

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
            // FIXME: group update path nodes by public key
            const updatePathNode = updatePath.nodes[i];
            for (const key of privateKeys) {
                // FIXME: is there a better way of doing this than trying to
                // decrypt every ciphertext with every key?  In theory, we
                // should know exactly which ciphertext was encrypted to which
                // key.
                try {
                    currPathSecret = await updatePathNode.encryptedPathSecret.decrypt(
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

            // FIXME: check that derived pubkey matches updatePathNode.publicKey

            newPath.push(new NodeData(
                currNodePriv,
                currNodePub,
                [], // FIXME: ???
                undefined,
                undefined, // FIXME:
            ))

            currPathSecret = await deriveSecret(this.hpke, currPathSecret, PATH);
        }

        const newTree = this.tree.replacePathToLeaf(fromNode, newPath.reverse());

        return new RatchetTreeView(this.hpke, this.nodeNum, newTree);
    }
}
