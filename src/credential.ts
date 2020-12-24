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

/** A user is identified by a credential, which is a signing key.
 *
 * https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#credentials
 */

import {CredentialType, SignatureScheme} from "./constants";
import {SigningPublicKey, Ed25519} from "./signatures";
import * as tlspl from "./tlspl";

export abstract class Credential {
    constructor(readonly credentialType: CredentialType) {}

    abstract verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
    abstract get identity(): Uint8Array;

    abstract get credentialEncoder(): tlspl.Encoder;
    static decode(buffer: Uint8Array, offset: number): [Credential, number] {
        const [[credentialType], offset1] = tlspl.decode(
            [tlspl.decodeUint16], buffer, offset,
        );
        switch (credentialType) {
            case CredentialType.Basic:
                return BasicCredential.decode(buffer, offset1);
            default:
                throw new Error("Unknown credential type");
        }
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint16(this.credentialType),
            this.credentialEncoder,
        ]);
    }
}

export class BasicCredential extends Credential {
    private publicKey: SigningPublicKey;
    constructor(
        readonly identity: Uint8Array,
        readonly signatureScheme: SignatureScheme,
        readonly signatureKey: Uint8Array,
    ) {
        super(CredentialType.Basic);
    }
    async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
        if (!this.publicKey) {
            switch (this.signatureScheme) {
                case SignatureScheme.ed25519:
                    this.publicKey = await Ed25519.deserializePublic(this.signatureKey);
                    break;
                // FIXME: other signature schemes
                default:
                    throw new Error("Unsupported signature scheme");
            }
        }
        return this.publicKey.verify(message, signature);
    }

    static decode(buffer: Uint8Array, offset: number): [BasicCredential, number] {
        const [[identity, signatureScheme, signatureKey], offset1] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(2),
                tlspl.decodeUint16,
                tlspl.decodeVariableOpaque(2),
            ],
            buffer, offset,
        );
        return [new BasicCredential(identity, signatureScheme, signatureKey), offset1];
    }
    get credentialEncoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.identity, 2),
            tlspl.uint16(this.signatureScheme),
            tlspl.variableOpaque(this.signatureKey, 2),
        ]);
    }
}

// FIXME: x509 certificate
