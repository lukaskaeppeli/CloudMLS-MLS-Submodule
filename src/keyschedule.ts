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
import {CipherSuite, cipherSuiteById} from "./ciphersuite";
import * as tlspl from "./tlspl";
import {left, right, directPath, root} from "./treemath";
import {GroupContext} from "./group";
import { base64ToBytes, bytesToBase64 } from "byte-base64";

export async function expandWithLabel(
    cipherSuite: CipherSuite,
    secret: Uint8Array,
    label: Uint8Array,
    context: Uint8Array,
    length: number,
): Promise<Uint8Array> {
    return cipherSuite.hpke.kdf.expand(
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
    cipherSuite: CipherSuite,
    secret: Uint8Array,
    label: Uint8Array,
): Promise<Uint8Array> {
    return expandWithLabel(
        cipherSuite, secret, label, EMPTY_BYTE_ARRAY, cipherSuite.hpke.kdf.extractLength,
    );
}

export interface Secrets {
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
    cipherSuite: CipherSuite,
    initSecret: Uint8Array,
    commitSecret: Uint8Array,
    groupContext: GroupContext,
    psk?: Uint8Array | undefined,
): Promise<Secrets> {
    const joinerSecret = await cipherSuite.hpke.kdf.extract(initSecret, commitSecret);
    return await generateSecretsFromJoinerSecret(
        cipherSuite, joinerSecret, commitSecret, groupContext, psk,
    );
}

export async function generateSecretsFromJoinerSecret(
    cipherSuite: CipherSuite,
    joinerSecret: Uint8Array,
    commitSecret: Uint8Array,
    groupContext: GroupContext,
    psk?: Uint8Array | undefined,
): Promise<Secrets> {
    if (psk === undefined) {
        psk = EMPTY_BYTE_ARRAY;
    }
    const memberIkm = await deriveSecret(cipherSuite, joinerSecret, MEMBER);
    const memberSecret = await cipherSuite.hpke.kdf.extract(memberIkm, psk);
    const welcomeSecret = await deriveSecret(cipherSuite, memberSecret, WELCOME);
    const epochSecret = await expandWithLabel(
        cipherSuite,
        welcomeSecret,
        EPOCH,
        tlspl.encode([groupContext.encoder]),
        cipherSuite.hpke.kdf.extractLength,
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
    ].map(label => deriveSecret(cipherSuite, epochSecret, label)))

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
    cipherSuite: CipherSuite,
    secret: Uint8Array,
    label: Uint8Array,
    node: number,
    generation: number,
    length: number,
): Promise<Uint8Array> {
    return expandWithLabel(
        cipherSuite,
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
    constructor(
        readonly cipherSuite: CipherSuite,
        public encryptionSecret: Uint8Array,
        readonly treeSize: number,
        public keyTree?: {[index: number]: Uint8Array}
    ) {
        if (!keyTree)
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
                this.cipherSuite, treeNodeSecret, TREE,
                leftChildNum, 0, this.cipherSuite.hpke.kdf.extractLength,
            ),
            deriveTreeSecret(
                this.cipherSuite, treeNodeSecret, TREE,
                rightChildNum, 0, this.cipherSuite.hpke.kdf.extractLength,
            ),
        ]);
        this.keyTree[leftChildNum] = leftSecret;
        this.keyTree[rightChildNum] = rightSecret;
    }
    async getRatchetsForLeaf(leafNum: number): Promise<[LenientHashRatchet, LenientHashRatchet]> {
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
                this.cipherSuite, leafSecret, HANDSHAKE,
                nodeNum, 0, this.cipherSuite.hpke.kdf.extractLength,
            ),
            deriveTreeSecret(
                this.cipherSuite, leafSecret, APPLICATION,
                nodeNum, 0, this.cipherSuite.hpke.kdf.extractLength,
            ),
        ]);
        leafSecret.fill(0);

        return [
            new LenientHashRatchet(this.cipherSuite, nodeNum, handshakeSecret),
            new LenientHashRatchet(this.cipherSuite, nodeNum, applicationSecret),
        ];
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#encryption-keys

export class HashRatchet {
    public generation;
    public savedKeys: {[index: number]: [Uint8Array, Uint8Array]}
    constructor(
        readonly cipherSuite: CipherSuite,
        readonly nodeNum: number,
        public secret: Uint8Array,
    ) {
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
                this.cipherSuite, this.secret, NONCE,
                this.nodeNum, this.generation, this.cipherSuite.hpke.aead.nonceLength,
            ),
            deriveTreeSecret(
                this.cipherSuite, this.secret, KEY,
                this.nodeNum, this.generation, this.cipherSuite.hpke.aead.keyLength,
            ),
            deriveTreeSecret(
                this.cipherSuite, this.secret, SECRET,
                this.nodeNum, this.generation, this.cipherSuite.hpke.kdf.extractLength,
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
    constructor(cipherSuite: CipherSuite, nodeNum: number, secret: Uint8Array, origSecret?: Uint8Array) {
        super(cipherSuite, nodeNum, secret);
        if (origSecret) {
            this.origSecret = origSecret
        } else {
            this.origSecret = secret
        }
    }

    serializeMinimal(): string {
        let json = {}
        json["cipherSuite"] = this.cipherSuite.id
        json["origSecret"] = bytesToBase64(this.origSecret)
        json["nodeNum"] = this.nodeNum

        return JSON.stringify(json)
    }

    static fromSerializedMinimal(serialized: string): LenientHashRatchet {
        let json = JSON.parse(serialized)

        return new LenientHashRatchet(
            cipherSuiteById[json["cipherSuite"]],
            json["nodeNum"],
            base64ToBytes(json["origSecret"]),
            base64ToBytes(json["origSecret"])
        )
    }

    serialize(): string {
        let json = {}
        json["generation"] = this.generation
        json["cipherSuite"] = this.cipherSuite.id
        json["secret"] = bytesToBase64(this.secret)
        json["origSecret"] = bytesToBase64(this.origSecret)
        json["nodeNum"] = this.nodeNum

        json["savedKeys"] = {}
        for (let key in this.savedKeys) {
            json["savedKeys"][key][0] = bytesToBase64(this.savedKeys[key][0])
            json["savedKeys"][key][1] = bytesToBase64(this.savedKeys[key][1])
        }

        return JSON.stringify(json)
    }

    static fromSerialized(serialized: string): LenientHashRatchet {
        let json = JSON.parse(serialized)

        let lenientHashRatchet = new LenientHashRatchet(
            cipherSuiteById[json["cipherSuite"]],
            json["nodeNum"],
            base64ToBytes(json["secret"]),
            base64ToBytes(json["origSecret"])
        )

        lenientHashRatchet.generation = json["generation"]

        for (let key in json["savedKeys"]) {
            lenientHashRatchet.savedKeys[key][0] = base64ToBytes(json["savedKeys"][key][0])
            lenientHashRatchet.savedKeys[key][1] = base64ToBytes(json["savedKeys"][key][1])
        }

        return lenientHashRatchet
    }

    async getKey(generation: number): Promise<[Uint8Array, Uint8Array]> {
        // TODO: This is very inefficient, if we derive the same keys over and over again,
        //       as keys and TreeSecrets are not cached.
        //       This happens if the messages are not stored in a local database like the 
        //       tdlib from Telegram, but are refetched again and again. Caching the derived
        //       keys is an option, but requires some effert as the complete MLS datastructures
        //       are recreated from a serialized version with each request.
        //       The only advantage of this approach is that we do not need to store every
        //       encryption key on the keyserver, which would require much more memory.
        let secret = this.origSecret;
        for (let i = 0; i < generation; i++) {
            const newSecret = await deriveTreeSecret(
                this.cipherSuite, secret, SECRET,
                this.nodeNum, i, this.cipherSuite.hpke.kdf.extractLength,
            );
            if (secret !== this.origSecret) {
                secret.fill(0);
            }
            secret = newSecret;
        }
        const [nonce, key] = await Promise.all([
            deriveTreeSecret(
                this.cipherSuite, secret, NONCE,
                this.nodeNum, generation, this.cipherSuite.hpke.aead.nonceLength,
            ),
            deriveTreeSecret(
                this.cipherSuite, secret, KEY,
                this.nodeNum, generation, this.cipherSuite.hpke.aead.keyLength,
            ),
        ]);
        return [nonce, key];

    }
}
