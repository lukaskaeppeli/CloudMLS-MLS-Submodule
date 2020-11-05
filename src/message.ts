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
import {EMPTY_BYTE_ARRAY} from "./constants";
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
        readonly encryptedPathSecret: HPKECiphertext,
    ) {}

    static decode(buffer: Uint8Array, offset: number): [UpdatePathNode, number] {
        const [[publicKey, encryptedPathSecret], offset1] = tlspl.decode(
            [tlspl.decodeVariableOpaque(2), HPKECiphertext.decode],
            buffer, offset,
        );
        return [new UpdatePathNode(publicKey, encryptedPathSecret), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.publicKey, 2),
            this.encryptedPathSecret.encoder,
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
