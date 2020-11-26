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

/** Message encodings
 */

import {HPKE, KEMPublicKey, KEMPrivateKey} from "./hpke/base";
import {EMPTY_BYTE_ARRAY, NONCE, KEY, ContentType, SenderType, ProposalType, ProposalOrRefType} from "./constants";
import {KeyPackage} from "./keypackage";
import {SigningPublicKey, SigningPrivateKey} from "./signatures";
import {Hash} from "./hash";
import {expandWithLabel, HashRatchet} from "./keyschedule";
import {GroupContext} from "./ratchettree";
import * as tlspl from "./tlspl";

/* ciphertext encrypted to an HPKE public key
 *
 * https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#update-paths
 */

export class HPKECiphertext {
    constructor(readonly kemOutput: Uint8Array, readonly ciphertext: Uint8Array) {}

    static async encrypt(
        hpke: HPKE, pkR: KEMPublicKey,
        aad: Uint8Array, pt: Uint8Array,
    ): Promise<HPKECiphertext> {
        const [enc, ct] = await hpke.sealBase(pkR, EMPTY_BYTE_ARRAY, aad, pt);
        return new HPKECiphertext(enc, ct);
    }
    decrypt(hpke: HPKE, skR: KEMPrivateKey, aad: Uint8Array): Promise<Uint8Array> {
        return hpke.openBase(this.kemOutput, skR, EMPTY_BYTE_ARRAY, aad, this.ciphertext);
    }

    static decode(buffer: Uint8Array, offset: number): [HPKECiphertext, number] {
        const [[kemOutput, ciphertext], offset1] = tlspl.decode(
            [tlspl.decodeVariableOpaque(2), tlspl.decodeVariableOpaque(2)],
            buffer, offset,
        );
        return [new HPKECiphertext(kemOutput, ciphertext), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.kemOutput, 2),
            tlspl.variableOpaque(this.ciphertext, 2),
        ]);
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#update-paths

export class UpdatePathNode {
    constructor(
        readonly publicKey: Uint8Array, // encoding of the node's KEMPublicKey
        readonly encryptedPathSecret: HPKECiphertext[],
    ) {}

    static decode(buffer: Uint8Array, offset: number): [UpdatePathNode, number] {
        const [[publicKey, encryptedPathSecret], offset1] = tlspl.decode(
            [tlspl.decodeVariableOpaque(2), tlspl.decodeVector(HPKECiphertext.decode, 4)],
            buffer, offset,
        );
        return [new UpdatePathNode(publicKey, encryptedPathSecret), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.publicKey, 2),
            tlspl.vector(this.encryptedPathSecret.map(x => x.encoder), 4),
        ]);
    }
}

export class UpdatePath {
    constructor(readonly leafKeyPackage: KeyPackage, readonly nodes: UpdatePathNode[]) {}

    static decode(buffer: Uint8Array, offset: number): [UpdatePath, number] {
        const [[leafKeyPackage, nodes], offset1] = tlspl.decode(
            [KeyPackage.decode, tlspl.decodeVector(UpdatePathNode.decode, 4)],
            buffer, offset,
        );
        return [new UpdatePath(leafKeyPackage, nodes), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            this.leafKeyPackage.encoder,
            tlspl.vector(this.nodes.map(x => x.encoder), 4),
        ]);
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#message-framing

export class Sender {
    constructor(
        readonly senderType: SenderType,
        readonly sender: number,
    ) {}

    static decode(buffer: Uint8Array, offset: number): [Sender, number] {
        const [[senderType, sender], offset1] = tlspl.decode(
            [tlspl.decodeUint8, tlspl.decodeUint8], buffer, offset,
        );
        return [new Sender(senderType, sender), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.senderType),
            tlspl.uint8(this.sender),
        ]);
    }
}

export class MLSPlaintext {
    readonly contentType: ContentType;
    constructor(
        readonly groupId: Uint8Array,
        readonly epoch: number,
        readonly sender: Sender,
        readonly authenticatedData: Uint8Array,
        readonly content: Uint8Array | Proposal | Commit,
        readonly signature: Uint8Array,
        readonly confirmationTag?: Uint8Array,
        readonly membershipTag?: Uint8Array,
    ) {
        this.contentType = MLSPlaintext.getContentType(content);
    }
    static getContentType(content: Uint8Array | Proposal | Commit) {
        if (content instanceof Uint8Array) {
            return ContentType.Application;
        } else if (content instanceof Proposal) {
            return ContentType.Proposal;
        } else if (content instanceof Commit) {
            return ContentType.Commit;
        } else {
            throw new Error("Unknown content type");
        }
    }
    static getContentDecode(contentType: ContentType) {
        switch (contentType) {
            case ContentType.Application:
                return tlspl.decodeVariableOpaque(4);
            case ContentType.Proposal:
                return Proposal.decode;
            case ContentType.Commit:
                return Commit.decode;
            default:
                throw new Error("Unknown content type");
        }
    }

    static async create(
        hash: Hash,
        groupId: Uint8Array,
        epoch: number,
        sender: Sender,
        authenticatedData: Uint8Array,
        content: Uint8Array | Proposal | Commit,
        signingKey: SigningPrivateKey,
        confirmationTag?: Uint8Array,
        context?: GroupContext,
        membershipKey?: Uint8Array,
    ): Promise<MLSPlaintext> {
        if (sender.senderType === SenderType.Member && context === undefined) {
            throw new Error("Group context must be provided for messages send by members");
        }
        if (content instanceof Commit && confirmationTag === undefined) {
            throw new Error("Confirmation tag must be present for commits");
        }
        const contentType = MLSPlaintext.getContentType(content);
        const mlsPlaintextTBS: Uint8Array = tlspl.encode([
            (sender.senderType === SenderType.Member ? context.encoder : tlspl.empty),
            tlspl.variableOpaque(groupId, 1),
            tlspl.uint64(epoch),
            sender.encoder,
            tlspl.variableOpaque(authenticatedData, 4),
            tlspl.uint8(contentType),
            content instanceof Uint8Array ?
                tlspl.variableOpaque(content, 4) :
                content.encoder,
        ]);
        const signature: Uint8Array = await signingKey.sign(mlsPlaintextTBS);
        const membershipTag =
            membershipKey ?
                await hash.mac(
                    membershipKey,
                    tlspl.encode([
                        tlspl.opaque(mlsPlaintextTBS),
                        tlspl.variableOpaque(signature, 2),
                        confirmationTag ?
                            tlspl.struct(
                                [tlspl.uint8(1), tlspl.variableOpaque(confirmationTag, 1)],
                            ) :
                            tlspl.uint8(0),
                    ]),
                ) :
                undefined;
        return new MLSPlaintext(
            groupId,
            epoch,
            sender,
            authenticatedData,
            content,
            signature,
            confirmationTag,
            membershipTag,
        );
    }

    async verify(
        hash: Hash,
        signingPubKey: SigningPublicKey,
        context?: GroupContext,
        membershipKey?: Uint8Array,
    ): Promise<boolean> {
        if (this.sender.senderType === SenderType.Member && context === undefined) {
            throw new Error("Group context must be provided for messages send by members");
        }
        if (this.content instanceof Commit && this.confirmationTag === undefined) {
            throw new Error("Confirmation tag must be present for commits");
        }
        const mlsPlaintextTBS: Uint8Array = tlspl.encode([
            (this.sender.senderType === SenderType.Member ? context.encoder : tlspl.empty),
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint64(this.epoch),
            this.sender.encoder,
            tlspl.variableOpaque(this.authenticatedData, 4),
            tlspl.uint8(this.contentType),
            this.content instanceof Uint8Array ?
                tlspl.variableOpaque(this.content, 4) :
                this.content.encoder,
        ]);
        if (await signingPubKey.verify(mlsPlaintextTBS, this.signature) === false) {
            return false;
        }
        // FIXME: verify confirmation tag?
        if (this.membershipTag) {
            if (membershipKey === undefined) {
                throw new Error("Membership tag is present, but membership key not supplied");
            }
            const mlsPlaintextTBM = tlspl.encode([
                tlspl.opaque(mlsPlaintextTBS),
                tlspl.variableOpaque(this.signature, 2),
                this.confirmationTag ?
                    tlspl.struct(
                        [tlspl.uint8(1), tlspl.variableOpaque(this.confirmationTag, 1)],
                    ) :
                    tlspl.uint8(0),
            ]);
            return await hash.verifyMac(
                membershipKey, mlsPlaintextTBM, this.membershipTag,
            );
        }
        return true;
    }

    static decode(buffer: Uint8Array, offset: number): [MLSPlaintext, number] {
        const [[groupId, epoch, sender, authenticatedData, contentType], offset1] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeUint64,
                Sender.decode,
                tlspl.decodeVariableOpaque(4),
                tlspl.decodeUint8,
            ],
            buffer, offset,
        );
        const [[content, signature, confirmationTag, membershipTag], offset2] = tlspl.decode(
            [
                MLSPlaintext.getContentDecode(contentType),
                tlspl.decodeVariableOpaque(2),
                tlspl.decodeOptional(tlspl.decodeVariableOpaque(1)),
                tlspl.decodeOptional(tlspl.decodeVariableOpaque(1)),
            ],
            buffer, offset1,
        );
        return [
            new MLSPlaintext(
                groupId, epoch, sender, authenticatedData, content, signature,
                confirmationTag, membershipTag,
            ), offset2,
        ];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint64(this.epoch),
            this.sender.encoder,
            tlspl.variableOpaque(this.authenticatedData, 4),
            tlspl.uint8(this.contentType),
            this.content instanceof Uint8Array ?
                tlspl.variableOpaque(this.content, 4) :
                this.content.encoder,
            tlspl.variableOpaque(this.signature, 2),
            this.confirmationTag ?
                tlspl.struct([
                    tlspl.uint8(1), tlspl.variableOpaque(this.confirmationTag, 1),
                ]) :
                tlspl.uint8(0),
            this.membershipTag ?
                tlspl.struct([
                    tlspl.uint8(1), tlspl.variableOpaque(this.membershipTag, 1),
                ]) :
                tlspl.uint8(0),
        ]);
    }
}

export class MLSCiphertext {
    constructor(
        readonly groupId: Uint8Array,
        readonly epoch: number,
        readonly contentType: ContentType,
        readonly authenticatedData: Uint8Array,
        readonly encryptedSenderData: Uint8Array,
        readonly ciphertext: Uint8Array,
    ) {}

    static async create(
        hpke: HPKE,
        plaintext: MLSPlaintext,
        contentRatchet: HashRatchet,
        senderDataSecret: Uint8Array,
    ): Promise<MLSCiphertext> {
        if (plaintext.sender.senderType !== SenderType.Member) {
            throw new Error("Sender must be a group member");
        }

        const mlsCiphertextContent = tlspl.encode([
            plaintext.content instanceof Uint8Array ?
                tlspl.variableOpaque(plaintext.content, 4) :
                plaintext.content.encoder,
            tlspl.variableOpaque(plaintext.signature, 2),
            plaintext.confirmationTag ?
                tlspl.struct([
                    tlspl.uint8(1), tlspl.variableOpaque(plaintext.confirmationTag, 1),
                ]) :
                tlspl.uint8(0),
            tlspl.variableOpaque(EMPTY_BYTE_ARRAY, 2), // FIXME: padding
        ]);
        const mlsCiphertextContentAad = tlspl.encode([
            tlspl.variableOpaque(plaintext.groupId, 1),
            tlspl.uint64(plaintext.epoch),
            tlspl.uint8(plaintext.contentType),
            tlspl.variableOpaque(plaintext.authenticatedData, 4),
        ]);

        // encrypt content
        const reuseGuard = new Uint8Array(4);
        window.crypto.getRandomValues(reuseGuard)
        const generation = contentRatchet.generation;
        const [contentNonce, contentKey] = await contentRatchet.getKey(generation);
        for (let i = 0; i < 4; i++) {
            contentNonce[i] ^= reuseGuard[i];
        }
        const ciphertext = await hpke.aead.seal(
            contentKey, contentNonce, mlsCiphertextContentAad, mlsCiphertextContent,
        );
        contentKey.fill(0);
        contentNonce.fill(0);

        // encrypt sender
        const mlsSenderData = tlspl.encode([
            tlspl.uint32(plaintext.sender.sender),
            tlspl.uint32(generation),
            tlspl.opaque(reuseGuard),
        ]);
        const mlsSenderDataAad = tlspl.encode([
            tlspl.variableOpaque(plaintext.groupId, 1),
            tlspl.uint64(plaintext.epoch),
            tlspl.uint8(plaintext.contentType),
        ]);
        const ciphertextSample = ciphertext.subarray(0, hpke.kdf.extractLength);
        const [senderDataKey, senderDataNonce] = await Promise.all([
            expandWithLabel(
                hpke, senderDataSecret, KEY, ciphertextSample, hpke.aead.keyLength,
            ),
            expandWithLabel(
                hpke, senderDataSecret, NONCE, ciphertextSample, hpke.aead.nonceLength,
            ),
        ]);
        const encryptedSenderData = await hpke.aead.seal(
            senderDataKey, senderDataNonce, mlsSenderDataAad, mlsSenderData,
        );
        return new MLSCiphertext(
            plaintext.groupId,
            plaintext.epoch,
            plaintext.contentType,
            plaintext.authenticatedData,
            encryptedSenderData,
            ciphertext,
        );
    }
    async decrypt(
        hpke: HPKE,
        contentRatchet: HashRatchet,
        senderDataSecret: Uint8Array,
    ): Promise<MLSPlaintext> {
        // decrypt sender
        const mlsSenderDataAad = tlspl.encode([
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint64(this.epoch),
            tlspl.uint8(this.contentType),
        ]);
        const ciphertextSample = this.ciphertext.subarray(0, hpke.kdf.extractLength);
        const [senderDataKey, senderDataNonce] = await Promise.all([
            expandWithLabel(
                hpke, senderDataSecret, KEY, ciphertextSample, hpke.aead.keyLength,
            ),
            expandWithLabel(
                hpke, senderDataSecret, NONCE, ciphertextSample, hpke.aead.nonceLength,
            ),
        ]);
        const mlsSenderData = await hpke.aead.open(
            senderDataKey, senderDataNonce, mlsSenderDataAad, this.encryptedSenderData,
        );
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[sender, generation, reuseGuard], ] = tlspl.decode(
            [
                tlspl.decodeUint32,
                tlspl.decodeUint32,
                tlspl.decodeOpaque(4),
            ],
            mlsSenderData, 0,
        );

        // decrypt content
        const mlsCiphertextContentAad = tlspl.encode([
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint64(this.epoch),
            tlspl.uint8(this.contentType),
            tlspl.variableOpaque(this.authenticatedData, 4),
        ]);
        const [contentNonce, contentKey] = await contentRatchet.getKey(generation);
        for (let i = 0; i < 4; i++) {
            contentNonce[i] ^= reuseGuard[i];
        }
        const mlsCiphertextContent = await hpke.aead.open(
            contentKey, contentNonce, mlsCiphertextContentAad, this.ciphertext,
        );
        contentKey.fill(0);
        contentNonce.fill(0);
        const contentDecode = MLSPlaintext.getContentDecode(this.contentType);
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[content, signature, confirmationTag, ], ] = tlspl.decode(
            [
                contentDecode,
                tlspl.decodeVariableOpaque(2),
                tlspl.decodeOptional(tlspl.decodeVariableOpaque(1)),
                tlspl.decodeOptional(tlspl.decodeVariableOpaque(2)),
            ],
            mlsCiphertextContent, 0,
        );
        return new MLSPlaintext(
            this.groupId,
            this.epoch,
            new Sender(SenderType.Member, sender),
            this.authenticatedData,
            content,
            signature,
            confirmationTag,
        );
    }

    static decode(
        buffer: Uint8Array, offset: number,
    ): [MLSCiphertext, number] {
        const [
            [
                groupId, epoch, contentType, authenticatedData, encryptedSenderData,
                ciphertext,
            ],
            offset1,
        ] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeUint8,
                tlspl.decodeUint8,
                tlspl.decodeVariableOpaque(4),
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeVariableOpaque(4),
            ],
            buffer, offset,
        );
        return [
            new MLSCiphertext(
                groupId, epoch, contentType, authenticatedData, encryptedSenderData,
                ciphertext,
            ),
            offset1,
        ];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint8(this.epoch),
            tlspl.uint8(this.contentType),
            tlspl.variableOpaque(this.authenticatedData, 4),
            tlspl.variableOpaque(this.encryptedSenderData, 1),
            tlspl.variableOpaque(this.ciphertext, 4),
        ]);
    }
}

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#proposals

export abstract class Proposal {
    constructor(
        readonly msgType: ProposalType,
    ) {}

    static decode(buffer: Uint8Array, offset: number): [Proposal, number] {
        const [msgType, offset1] = tlspl.decodeUint8(buffer, offset);
        switch (msgType) {
            case ProposalType.Add:
                return Add.decode(buffer, offset1);
            case ProposalType.Update:
                return Update.decode(buffer, offset1);
            case ProposalType.Remove:
                return Remove.decode(buffer, offset1);
            default:
                throw new Error("Unknown proposal type");
        }
    }
    abstract get encoder(): tlspl.Encoder;
}

export class Add extends Proposal {
    constructor(
        readonly keyPackage: KeyPackage,
    ) { super(ProposalType.Add); }

    static decode(buffer: Uint8Array, offset: number): [Add, number] {
        const [keyPackage, offset1] = KeyPackage.decode(buffer, offset);
        return [new Add(keyPackage), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.msgType),
            this.keyPackage.encoder,
        ]);
    }
}

export class Update extends Proposal {
    constructor(
        readonly keyPackage: KeyPackage,
        readonly privateKey?: KEMPrivateKey, // when we're updating our own
    ) { super(ProposalType.Update); }

    static decode(buffer: Uint8Array, offset: number): [Add, number] {
        const [keyPackage, offset1] = KeyPackage.decode(buffer, offset);
        return [new Update(keyPackage), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.msgType),
            this.keyPackage.encoder,
        ]);
    }
}

export class Remove extends Proposal {
    constructor(
        readonly removed: number,
    ) { super(ProposalType.Remove); }

    static decode(buffer: Uint8Array, offset: number): [Remove, number] {
        const [removed, offset1] = tlspl.decodeUint32(buffer, offset);
        return [new Remove(removed), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.msgType),
            tlspl.uint32(this.removed),
        ]);
    }
}

// FIXME: more proposals

// https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#commit

export abstract class ProposalOrRef {
    constructor(
        readonly proposalOrRef: ProposalOrRefType, // originally named "type"
    ) {}

    static decode(buffer: Uint8Array, offset: number): [ProposalOrRef, number] {
        const [proposalOrRef, offset1] = tlspl.decodeUint8(buffer, offset);
        switch (proposalOrRef) {
            case ProposalOrRefType.Proposal:
                return ProposalWrapper.decode(buffer, offset1);
            case ProposalOrRefType.Reference:
                return Reference.decode(buffer, offset1);
            default:
                throw new Error("Unknown proposalOrRef type");
        }
    }
    abstract get encoder(): tlspl.Encoder;
}

export class ProposalWrapper extends ProposalOrRef {
    constructor(readonly proposal: Proposal) { super(ProposalOrRefType.Proposal); }

    static decode(buffer: Uint8Array, offset: number): [ProposalWrapper, number] {
        const [proposal, offset1] = Proposal.decode(buffer, offset);
        return [new ProposalWrapper(proposal), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.proposalOrRef),
            this.proposal.encoder,
        ]);
    }
}

export class Reference extends ProposalOrRef {
    constructor(readonly hash: Uint8Array) { super(ProposalOrRefType.Reference); }

    static decode(buffer: Uint8Array, offset: number): [Reference, number] {
        const [hash, offset1] = tlspl.decodeVariableOpaque(1)(buffer, offset);
        return [new Reference(hash), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint8(this.proposalOrRef),
            tlspl.variableOpaque(this.hash, 1),
        ]);
    }
}

export class Commit {
    constructor(
        readonly proposals: ProposalOrRef[],
        readonly updatePath?: UpdatePath,
    ) {}

    static decode(buffer: Uint8Array, offset: number): [Commit, number] {
        const [[proposals, updatePath], offset1] = tlspl.decode(
            [
                tlspl.decodeVector(ProposalOrRef.decode, 4),
                tlspl.decodeOptional(UpdatePath.decode),
            ],
            buffer, offset,
        );
        return [new Commit(proposals, updatePath), offset1];
    }
    get encoder(): tlspl.Encoder {
        if (this.updatePath === undefined) {
            return tlspl.struct([
                tlspl.vector(this.proposals.map(x => x.encoder), 4),
                tlspl.uint8(0),
            ]);
        } else {
            return tlspl.struct([
                tlspl.vector(this.proposals.map(x => x.encoder), 4),
                tlspl.uint8(1),
                this.updatePath.encoder,
            ]);
        }
    }
}
