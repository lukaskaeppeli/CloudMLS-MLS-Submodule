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

/** Each user has a key package per room, which has the user's credential and an
 * HPKE public key that can be used to encrypt data for that user.
 *
 * https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#key-packages
 */

import {EMPTY_BYTE_ARRAY, ExtensionType, ProtocolVersion, NodeType} from "./constants";
import {CipherSuite, cipherSuiteById} from "./ciphersuite";
import {Credential} from "./credential";
import {SigningPrivateKey} from "./signatures";
import {KEMPublicKey} from "./hpke/base";
import * as tlspl from "./tlspl";
import { base64ToBytes, bytesToBase64 } from "byte-base64";

export abstract class Extension {
    constructor(readonly extensionType: ExtensionType) {}

    abstract get extensionData(): Uint8Array;
    static decode(buffer: Uint8Array, offset: number): [Extension, number] {
        const [[extensionType, extensionData], offset1] = tlspl.decode(
            [tlspl.decodeUint8, tlspl.decodeVariableOpaque(2)], buffer, offset,
        );
        switch (extensionType) {
            case ExtensionType.Capabilities:
            {
                // eslint-disable-next-line comma-dangle, array-bracket-spacing
                const [extension, ] = Capabilities.decode(extensionData);
                return [extension, offset1];
            }
            case ExtensionType.RatchetTree:
            {
                // eslint-disable-next-line comma-dangle, array-bracket-spacing
                const [extension, ] = RatchetTree.decode(extensionData);
                return [extension, offset1];
            }
            case ExtensionType.ParentHash:
            {
                // eslint-disable-next-line comma-dangle, array-bracket-spacing
                const [extension, ] = ParentHash.decode(extensionData);
                return [extension, offset1];
            }
            case ExtensionType.Lifetime:
            {
                const [extension, ] = Lifetime.decode(extensionData);
                return [extension, offset1];
            }

            default:
                return [new UnknownExtension(extensionType, extensionData), offset1];
        }
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.extensionType),
            tlspl.variableOpaque(this.extensionData, 2),
        ]);
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#client-capabilities

export class Capabilities extends Extension {
    constructor(
        readonly versions: ProtocolVersion[],
        readonly ciphersuites: number[],
        readonly extensions: ExtensionType[],
    ) {
        super(ExtensionType.Capabilities);
    }
    get extensionData(): Uint8Array {
        return tlspl.encode([
            tlspl.vector(this.versions.map(tlspl.uint16), 1),
        ]);
    }
    static decode(buffer: Uint8Array, offset = 0): [Capabilities, number] {
        const [[versions, ciphersuites, extensions], offset1] = tlspl.decode(
            [
                tlspl.decodeVector(tlspl.decodeUint16, 1),
                tlspl.decodeVector(tlspl.decodeUint16, 1),
                tlspl.decodeVector(tlspl.decodeUint16, 1),
            ],
            buffer,
            offset,
        );
        return [new Capabilities(versions, ciphersuites, extensions), offset1];
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#parent-hash

export class ParentHash extends Extension {
    constructor(readonly parentHash: Uint8Array) {
        super(ExtensionType.ParentHash);
    }
    get extensionData(): Uint8Array {
        return tlspl.encode([
            tlspl.variableOpaque(this.parentHash, 1),
        ]);
    }
    static decode(buffer: Uint8Array, offset = 0): [ParentHash, number] {
        const [[parentHash], offset1] = tlspl.decode(
            [tlspl.decodeVariableOpaque(1)], buffer, offset,
        );
        return [new ParentHash(parentHash), offset1];
    }
}

export class ParentNode {
    private hpkeKey: KEMPublicKey;
    constructor(
        readonly publicKey: Uint8Array,
        readonly unmergedLeaves: number[],
        readonly parentHash: Uint8Array,
    ) {}

    async getHpkeKey(cipherSuite: CipherSuite): Promise<KEMPublicKey> {
        if (!this.hpkeKey) {
            this.hpkeKey = await cipherSuite.hpke.kem.deserializePublic(this.publicKey);
        }
        return this.hpkeKey;
    }

    static decode(buffer: Uint8Array, offset: number): [ParentNode, number] {
        const [[publicKey, unmergedLeaves, parentHash], offset1] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(2),
                tlspl.decodeVector(tlspl.decodeUint32, 4),
                tlspl.decodeVariableOpaque(1),
            ],
            buffer, offset,
        );
        return [new ParentNode(publicKey, unmergedLeaves, parentHash), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.publicKey, 2),
            tlspl.vector(this.unmergedLeaves.map(tlspl.uint32), 4),
            tlspl.variableOpaque(this.parentHash || EMPTY_BYTE_ARRAY /* FIXME: ??? */, 1),
        ]);
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#ratchet-tree-extension

function decodeRatchetTreeNode(buffer: Uint8Array, offset: number)
: [KeyPackage | ParentNode, number] {
    const [[nodeType], offset1] = tlspl.decode([tlspl.decodeUint8], buffer, offset);
    switch (nodeType) {
        case NodeType.Leaf:
            return KeyPackage.decode(buffer, offset1);
        case NodeType.Parent:
            return ParentNode.decode(buffer, offset1);
        default:
            throw new Error("Invalid node type");
    }
}

export class RatchetTree extends Extension {
    constructor(readonly nodes: Array<KeyPackage | ParentNode | undefined>) {
        super(ExtensionType.RatchetTree);
    }
    get extensionData(): Uint8Array {
        return tlspl.encode([
            tlspl.vector(this.nodes.map((node) => {
                if (node === undefined) {
                    return tlspl.uint8(0)
                } else {
                    return tlspl.struct([
                        tlspl.uint8(1),
                        tlspl.uint8(
                            node instanceof KeyPackage ? NodeType.Leaf : NodeType.Parent,
                        ),
                        node.encoder,
                    ]);
                }
            }), 4),
        ]);
    }
    static decode(buffer: Uint8Array, offset = 0): [RatchetTree, number] {
        const [[nodes], offset1] = tlspl.decode(
            [tlspl.decodeVector(tlspl.decodeOptional(decodeRatchetTreeNode), 4)],
            buffer, offset,
        );
        return [new RatchetTree(nodes), offset1];
    }
}

export class Lifetime extends Extension {
    constructor(readonly not_before: number, readonly not_after: number) {
        super(ExtensionType.Lifetime)
    }
    get extensionData(): Uint8Array {
        return tlspl.encode([
            tlspl.uint64(this.not_before),
            tlspl.uint64(this.not_after)
        ]);
    }

    static decode(buffer: Uint8Array, offset = 0): [Lifetime, number] {
        const [not_before, offset1] = tlspl.decodeUint64(buffer, offset)
        const [not_after, offset2] = tlspl.decodeUint64(buffer, offset1)

        return [new Lifetime(not_before, not_after), offset2]
    }

    /**
     * Returns if the keypackage is valid at this point in time (future_time == undefined)
     * or valid at now + future_time
     * 
     * @param future_time possibly undefined, time from now on in milliseconds
     * @returns true if the keypackage is valid at specified time
     */
    is_valid(future_time?: number): Boolean {
        let now_time = new Date().getTime();
        if (future_time)
            return (now_time > this.not_before && now_time + future_time < this.not_after)

        return (now_time > this.not_before && now_time < this.not_after)
    }
}

// FIXME: more extensions

class UnknownExtension extends Extension {
    constructor(
        readonly extensionType: ExtensionType,
        readonly extensionData: Uint8Array,
    ) { super(extensionType); }
}

export class KeyPackage {
    constructor(
        readonly version: ProtocolVersion,
        readonly cipherSuite: CipherSuite,
        readonly hpkeInitKey: Uint8Array,
        readonly credential: Credential,
        readonly extensions: Extension[],
        public unsignedEncoding: Uint8Array,
        public signature: Uint8Array,
        readonly signingKey?: SigningPrivateKey,
        private hpkeKey?: KEMPublicKey,
        private hashCache?: Uint8Array
    ) {}

    static async create(
        version: ProtocolVersion,
        cipherSuite: CipherSuite,
        hpkeInitKey: Uint8Array,
        credential: Credential,
        extensions: Extension[],
        signingKey: SigningPrivateKey,
    ): Promise<KeyPackage> {
        const unsignedEncoding: Uint8Array = tlspl.encode([
            tlspl.uint8(version),
            tlspl.uint16(cipherSuite.id),
            tlspl.variableOpaque(hpkeInitKey, 2),
            credential.encoder,
            tlspl.vector(extensions.map(ext => ext.encoder), 4),
        ]);
        const signature: Uint8Array = await signingKey.sign(unsignedEncoding);
        return new KeyPackage(
            version, cipherSuite, hpkeInitKey, credential, extensions,
            unsignedEncoding, signature, signingKey,
        );
    }

    async toJSON() {
        let json = {}

        if (this.hpkeKey != undefined) {
            json["hpkeKey"] = bytesToBase64(await this.hpkeKey.serialize())
        }

        if (this.hashCache != undefined) {
            json["hashCache"] = bytesToBase64(this.hashCache)
        }

        json["version"] = this.version.valueOf()
        json["cipherSuite"] = this.cipherSuite.id
        json["hpkeInitKey"] = bytesToBase64(this.hpkeInitKey)
        let credential_buffer = new Uint8Array(this.credential.encoder.length)
        this.credential.encoder.writeToBuffer(credential_buffer, 0)
        json["credential"] = bytesToBase64(credential_buffer)

        json["extensions"] = []
        let extension_num = 0
        for (let extension of this.extensions) {
            let extension_buffer = new Uint8Array(extension.encoder.length)
            extension.encoder.writeToBuffer(extension_buffer, 0)
            json["extensions"][extension_num] = bytesToBase64(extension_buffer)
            extension_num++
        }

        json["usignedEncoding"] = bytesToBase64(this.unsignedEncoding)
        json["signature"] = bytesToBase64(this.signature)

        if (this.signingKey != undefined) {
            json["signingKey"] = bytesToBase64(await this.signingKey.serialize())
        }

        return json
    }

    static async fromJSON(json: any): Promise<KeyPackage> {
        let extensions = []
        if (json["extensions"] != undefined) {
            for (let extension of json["extensions"]) {
                extensions.push(Extension.decode(base64ToBytes(extension), 0)[0])
            }
        }

        let cipherSuite = cipherSuiteById[json["cipherSuite"]]

        let signingKey = undefined
        if (json["signingKey"] != undefined) {
            signingKey = await cipherSuite.signatureScheme.deserializePrivate(base64ToBytes(json["signingKey"]))
        }

        let kemPublicKey = undefined
        if (json["hpkeKey"] != undefined) {
            kemPublicKey = await cipherSuite.hpke.kem.deserializePublic(base64ToBytes(json["hpkeKey"]))
        }

        let hashCache = undefined
        if (json["hashCache"] != undefined) {
            hashCache = base64ToBytes(json["hashCache"])
        }

        let keyPackage = new KeyPackage(
            json["version"],
            cipherSuite,
            base64ToBytes(json["hpkeInitKey"]),
            Credential.decode(base64ToBytes(json["credential"]), 0)[0],
            extensions,
            base64ToBytes(json["usignedEncoding"]),
            base64ToBytes(json["signature"]),
            signingKey,
            kemPublicKey,
            hashCache
        )

        return keyPackage
    }


    checkSignature(): Promise<boolean> {
        return this.credential.verify(this.unsignedEncoding, this.signature);
    }
    async getHpkeKey(): Promise<KEMPublicKey> {
        if (!this.hpkeKey) {
            this.hpkeKey = await this.cipherSuite.hpke.kem.deserializePublic(this.hpkeInitKey);
        }
        return this.hpkeKey;
    }

    async addExtension(extension: Extension): Promise<void> {
        if (!this.signingKey) {
            throw new Error("Cannot change extensions without a signing key");
        }
        this.extensions.push(extension);
        this.unsignedEncoding = tlspl.encode([
            tlspl.uint8(this.version),
            tlspl.uint16(this.cipherSuite.id),
            tlspl.variableOpaque(this.hpkeInitKey, 2),
            this.credential.encoder,
            tlspl.vector(this.extensions.map(ext => ext.encoder), 4),
        ]);
        this.signature = await this.signingKey.sign(this.unsignedEncoding);
    }

    async hash(): Promise<Uint8Array> {
        if (!this.hashCache) {
            const encoded = tlspl.encode([this.encoder]);
            this.hashCache = await this.cipherSuite.hash.hash(encoded);
        }
        return this.hashCache;
    }

    static decode(buffer: Uint8Array, offset: number): [KeyPackage, number] {
        const [
            [version, cipherSuiteId, hpkeInitKey, credential, extensions],
            offset1,
        ] = tlspl.decode(
            [
                tlspl.decodeUint8,
                tlspl.decodeUint16,
                tlspl.decodeVariableOpaque(2),
                Credential.decode,
                tlspl.decodeVector(Extension.decode, 4),
            ],
            buffer, offset,
        );
        const cipherSuite = cipherSuiteById[cipherSuiteId];
        if (!cipherSuite) {
            throw new Error("Unknown ciphersuite");
        }
        const [[signature], offset2] = tlspl.decode(
            [tlspl.decodeVariableOpaque(2)], buffer, offset1,
        );
        return [
            new KeyPackage(
                version, cipherSuite, hpkeInitKey, credential, extensions,
                buffer.subarray(offset, offset1), signature,
            ),
            offset2,
        ];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.version),
            tlspl.uint16(this.cipherSuite.id),
            tlspl.variableOpaque(this.hpkeInitKey, 2),
            this.credential.encoder,
            tlspl.vector(this.extensions.map(ext => ext.encoder), 4),
            tlspl.variableOpaque(this.signature, 2),
        ]);
    }
}
