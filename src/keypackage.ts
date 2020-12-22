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

import {ExtensionType, ProtocolVersion, NodeType} from "./constants";
import {CipherSuite, cipherSuiteById} from "./ciphersuite";
import {Credential} from "./credential";
import {SigningPrivateKey} from "./signatures";
import {KEMPublicKey} from "./hpke/base";
import * as tlspl from "./tlspl";

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
        ])
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
        )
        return [new Capabilities(versions, ciphersuites, extensions), offset1];
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
            this.hpkeKey = await cipherSuite.hpke.kem.deserialize(this.publicKey);
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
            tlspl.variableOpaque(this.parentHash, 1),
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

// FIXME: more extensions

class UnknownExtension extends Extension {
    constructor(
        readonly extensionType: ExtensionType,
        readonly extensionData: Uint8Array,
    ) { super(extensionType); }
}

export class KeyPackage {
    private hpkeKey: KEMPublicKey;
    constructor(
        readonly version: ProtocolVersion,
        readonly cipherSuite: CipherSuite,
        readonly hpkeInitKey: Uint8Array,
        readonly credential: Credential,
        readonly extensions: Extension[],
        readonly unsignedEncoding: Uint8Array,
        readonly signature: Uint8Array,
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
            unsignedEncoding, signature,
        );
    }

    checkSignature(): Promise<boolean> {
        return this.credential.verify(this.unsignedEncoding, this.signature);
    }
    async getHpkeKey(): Promise<KEMPublicKey> {
        if (!this.hpkeKey) {
            this.hpkeKey = await this.cipherSuite.hpke.kem.deserialize(this.hpkeInitKey);
        }
        return this.hpkeKey;
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
