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
import {EMPTY_BYTE_ARRAY, ProposalType, ProposalOrRefType} from "./constants";
import {KeyPackage} from "./keypackage";
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
