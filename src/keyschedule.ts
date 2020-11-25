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

/** The key schedule determines how to derive keys for various uses.
 *
 * https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#key-schedule
 */

import {concatUint8Array} from "./util";
import {
    APPLICATION,
    AUTHENTICATION,
    CONFIRM,
    EMPTY_BYTE_ARRAY,
    ENCRYPTION,
    EPOCH,
    EXPORTER,
    EXTERNAL,
    HANDSHAKE,
    INIT,
    KEY,
    MEMBER,
    MEMBERSHIP,
    MLS10,
    NONCE,
    RESUMPTION,
    SECRET,
    SENDER_DATA,
    TREE,
    WELCOME,
} from "./constants";
import {HPKE} from "./hpke/base";
import * as tlspl from "./tlspl";
import {left, right, directPath, root} from "./treemath";

export async function expandWithLabel(
    hpke: HPKE,
    secret: Uint8Array,
    label: Uint8Array,
    context: Uint8Array,
    length: number,
): Promise<Uint8Array> {
    return hpke.kdf.expand(
        secret,
        tlspl.encode([
            tlspl.uint16(length),
            tlspl.variableOpaque(concatUint8Array([MLS10, label]), 1),
            tlspl.variableOpaque(context, 4),
        ]),
        length,
    );
}

export async function deriveSecret(
    hpke: HPKE,
    secret: Uint8Array,
    label: Uint8Array,
): Promise<Uint8Array> {
    return expandWithLabel(hpke, secret, label, EMPTY_BYTE_ARRAY, hpke.kdf.extractLength);
}

interface Secrets {
    joinerSecret: Uint8Array;
    memberSecret: Uint8Array;
    welcomeSecret: Uint8Array;
    senderDataSecret: Uint8Array;
    encryptionSecret: Uint8Array;
    exporterSecret: Uint8Array;
    authenticationSecret: Uint8Array;
    externalSecret: Uint8Array;
    confirmationKey: Uint8Array;
    membershipKey: Uint8Array;
    resumptionSecret: Uint8Array;
    initSecret: Uint8Array;
}

export async function generateSecrets(
    hpke: HPKE,
    initSecret: Uint8Array,
    commitSecret: Uint8Array,
    groupContext: Uint8Array,
    psk?: Uint8Array,
): Promise<Secrets> {
    const joinerSecret = await hpke.kdf.extract(initSecret, commitSecret);
    return await generateSecretsFromJoinerSecret(
        hpke, joinerSecret, commitSecret, groupContext, psk,
    );
}

export async function generateSecretsFromJoinerSecret(
    hpke: HPKE,
    joinerSecret: Uint8Array,
    commitSecret: Uint8Array,
    groupContext: Uint8Array,
    psk?: Uint8Array,
): Promise<Secrets> {
    if (psk === undefined) {
        psk = EMPTY_BYTE_ARRAY;
    }
    const memberIkm = await deriveSecret(hpke, joinerSecret, MEMBER);
    const memberSecret = await hpke.kdf.extract(memberIkm, psk);
    const welcomeSecret = await deriveSecret(hpke, memberSecret, WELCOME);
    const epochSecret = await expandWithLabel(
        hpke,
        welcomeSecret,
        EPOCH,
        groupContext,
        hpke.kdf.extractLength,
    );

    const [
        senderDataSecret,
        encryptionSecret,
        exporterSecret,
        authenticationSecret,
        externalSecret,
        confirmationKey,
        membershipKey,
        resumptionSecret,
        nextInitSecret,
    ] = await Promise.all([
        SENDER_DATA,
        ENCRYPTION,
        EXPORTER,
        AUTHENTICATION,
        EXTERNAL,
        CONFIRM,
        MEMBERSHIP,
        RESUMPTION,
        INIT,
    ].map(label => deriveSecret(hpke, epochSecret, label)))

    return {
        joinerSecret,
        memberSecret,
        welcomeSecret,
        senderDataSecret,
        encryptionSecret,
        exporterSecret,
        authenticationSecret,
        externalSecret,
        confirmationKey,
        membershipKey,
        resumptionSecret,
        initSecret: nextInitSecret,
    };
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#secret-tree-secret-tree

async function deriveTreeSecret(
    hpke: HPKE,
    secret: Uint8Array,
    label: Uint8Array,
    node: number,
    generation: number,
    length: number,
): Promise<Uint8Array> {
    return expandWithLabel(
        hpke,
        secret,
        label,
        tlspl.encode([
            tlspl.uint32(node),
            tlspl.uint32(generation),
        ]),
        length,
    )
}

export class SecretTree {
    private keyTree: {[index: number]: Uint8Array};
    constructor(
        readonly hpke: HPKE,
        encryptionSecret: Uint8Array,
        readonly treeSize: number,
    ) {
        this.keyTree = {[root(treeSize)]: encryptionSecret};
    }
    private async deriveChildSecrets(nodeNum: number): Promise<void> {
        const treeNodeSecret = this.keyTree[nodeNum];
        this.keyTree[nodeNum].fill(0);
        delete this.keyTree[nodeNum];
        const [leftChildNum, rightChildNum] =
            [left(nodeNum), right(nodeNum, this.treeSize)];
        const [leftSecret, rightSecret] = await Promise.all([
            deriveTreeSecret(
                this.hpke, treeNodeSecret, TREE,
                leftChildNum, 0, this.hpke.kdf.extractLength,
            ),
            deriveTreeSecret(
                this.hpke, treeNodeSecret, TREE,
                rightChildNum, 0, this.hpke.kdf.extractLength,
            ),
        ]);
        this.keyTree[leftChildNum] = leftSecret;
        this.keyTree[rightChildNum] = rightSecret;
    }
    async getRatchetsForLeaf(leafNum: number): Promise<[HashRatchet, HashRatchet]> {
        const nodeNum = leafNum * 2;
        const path = directPath(nodeNum, this.treeSize);
        const nodesToDerive = [];
        for (const node of path) {
            nodesToDerive.push(node);
            if (node in this.keyTree) {
                break;
            }
        }
        if (!(nodeNum in this.keyTree)) {
            if (!(nodesToDerive[nodesToDerive.length - 1] in this.keyTree)) {
                throw new Error("Ratchet for leaf has already been derived");
            }
            while (nodesToDerive.length) {
                const node = nodesToDerive.pop();
                await this.deriveChildSecrets(node);
            }
        }
        const leafSecret = this.keyTree[nodeNum];
        delete this.keyTree[nodeNum];

        const [handshakeSecret, applicationSecret] = await Promise.all([
            deriveTreeSecret(
                this.hpke, leafSecret, HANDSHAKE,
                nodeNum, 0, this.hpke.kdf.extractLength,
            ),
            deriveTreeSecret(
                this.hpke, leafSecret, APPLICATION,
                nodeNum, 0, this.hpke.kdf.extractLength,
            ),
        ]);
        leafSecret.fill(0);

        return [
            new HashRatchet(this.hpke, nodeNum, handshakeSecret),
            new HashRatchet(this.hpke, nodeNum, applicationSecret),
        ];
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys

export class HashRatchet {
    public generation;
    private savedKeys: {[index: number]: [Uint8Array, Uint8Array]}
    constructor(readonly hpke: HPKE, readonly nodeNum: number, private secret: Uint8Array) {
        this.generation = 0;
        this.savedKeys = {};
    }
    async getKey(generation: number): Promise<[Uint8Array, Uint8Array]> {
        if (generation < this.generation) {
            if (generation in this.savedKeys) {
                const key = this.savedKeys[generation];
                delete this.savedKeys[generation];
                return key;
            } else {
                throw new Error("Key was already fetched");
            }
        } else {
            while (this.generation < generation) {
                this.savedKeys[this.generation] = await this.advance();
            }
            return await this.advance();
        }
    }
    private async advance(): Promise<[Uint8Array, Uint8Array]> {
        const [nonce, key, nextSecret] = await Promise.all([
            deriveTreeSecret(
                this.hpke, this.secret, NONCE,
                this.nodeNum, this.generation, this.hpke.aead.nonceLength,
            ),
            deriveTreeSecret(
                this.hpke, this.secret, KEY,
                this.nodeNum, this.generation, this.hpke.aead.keyLength,
            ),
            deriveTreeSecret(
                this.hpke, this.secret, SECRET,
                this.nodeNum, this.generation, this.hpke.kdf.extractLength,
            ),
        ]);
        this.secret.fill(0);
        this.generation++;
        this.secret = nextSecret;
        return [nonce, key];
    }
}

/** Like HashRatchet, but allows you to re-derive keys that were already
 * fetched.  Using this function will void your warranty.
 */
export class LenientHashRatchet extends HashRatchet {
    private origSecret: Uint8Array;
    constructor(hpke: HPKE, nodeNum: number, secret: Uint8Array) {
        super(hpke, nodeNum, secret);
        this.origSecret = new Uint8Array(secret);
    }
    async getKey(generation: number): Promise<[Uint8Array, Uint8Array]> {
        try {
            return await super.getKey(generation);
        } catch {
            let secret = this.origSecret;
            for (let i = 0; i < generation; i++) {
                const newSecret = await deriveTreeSecret(
                    this.hpke, secret, SECRET,
                    this.nodeNum, i, this.hpke.kdf.extractLength,
                );
                if (secret !== this.origSecret) {
                    secret.fill(0);
                }
                secret = newSecret;
            }
            const [nonce, key] = await Promise.all([
                deriveTreeSecret(
                    this.hpke, secret, NONCE,
                    this.nodeNum, generation, this.hpke.aead.nonceLength,
                ),
                deriveTreeSecret(
                    this.hpke, secret, KEY,
                    this.nodeNum, generation, this.hpke.aead.keyLength,
                ),
            ]);
            return [nonce, key];
        }
    }
}
