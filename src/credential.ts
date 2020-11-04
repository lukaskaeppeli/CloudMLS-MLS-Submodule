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

export class BasicCredential {
    private publicKey: SigningPublicKey;
    constructor(
        readonly identity: Uint8Array,
        readonly signatureScheme: SignatureScheme,
        readonly signatureKey: Uint8Array,
    ) {}
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
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.identity, 2),
            tlspl.uint16(this.signatureScheme),
            tlspl.variableOpaque(this.signatureKey, 2),
        ]);
    }
}

export class Credential {
    readonly signatureScheme: SignatureScheme;
    constructor(
        readonly credentialType: CredentialType,
        readonly credential: BasicCredential, // FIXME: or x509 certificate
    ) {}
    verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
        return this.credential.verify(message, signature);
    }

    static decode(buffer: Uint8Array, offset: number): [Credential, number] {
        const [[credentialType], offset1] = tlspl.decode(
            [tlspl.decodeUint16], buffer, offset,
        );
        switch (credentialType) {
            case CredentialType.Basic:
            {
                const [[basicCredential], offset2] = tlspl.decode(
                    [BasicCredential.decode], buffer, offset1,
                );
                return [
                    new Credential(CredentialType.Basic, basicCredential),
                    offset2,
                ];
            }
            default:
                throw new Error("Unsupported credential type");
        }
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint16(this.credentialType),
            this.credential.encoder,
        ]);
    }
}
