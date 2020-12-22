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

/** Welcoming new members.
 *
 * https://github.com/mlswg/mls-protocol/blob/master/draft-ietf-mls-protocol.md#welcoming-new-members
 */

import {eqUint8Array} from "./util";
import {KEMPrivateKey} from "./hpke/base";
import {deriveSecret} from "./keyschedule";
import {EMPTY_BYTE_ARRAY, MEMBER, WELCOME, NONCE, KEY} from "./constants";
import {CipherSuite, cipherSuiteById} from "./ciphersuite";
import {KeyPackage, Extension} from "./keypackage";
import {HPKECiphertext} from "./message";
import {SigningPrivateKey, SigningPublicKey} from "./signatures";
import * as tlspl from "./tlspl";

export class GroupInfo {
    constructor(
        readonly groupId: Uint8Array,
        readonly epoch: number,
        readonly treeHash: Uint8Array,
        readonly confirmedTranscriptHash: Uint8Array,
        readonly extensions: Extension[],
        readonly confirmationTag: Uint8Array,
        readonly signerIndex: number,
        readonly unsignedEncoding: Uint8Array,
        readonly signature: Uint8Array,
    ) {}

    static async create(
        groupId: Uint8Array,
        epoch: number,
        treeHash: Uint8Array,
        confirmedTranscriptHash: Uint8Array,
        extensions: Extension[],
        confirmationTag: Uint8Array,
        signerIndex: number,
        signingKey: SigningPrivateKey,
    ): Promise<GroupInfo> {
        const unsignedEncoding: Uint8Array = tlspl.encode([
            tlspl.variableOpaque(groupId, 1),
            tlspl.uint64(epoch),
            tlspl.variableOpaque(treeHash, 1),
            tlspl.variableOpaque(confirmedTranscriptHash, 1),
            tlspl.vector(extensions.map(ext => ext.encoder), 4),
            tlspl.variableOpaque(confirmationTag, 1),
            tlspl.uint32(signerIndex),
        ]);
        const signature: Uint8Array = await signingKey.sign(unsignedEncoding);
        return new GroupInfo(
            groupId, epoch, treeHash, confirmedTranscriptHash, extensions,
            confirmationTag, signerIndex, unsignedEncoding, signature,
        );
    }

    checkSignature(pubKey: SigningPublicKey): Promise<boolean> {
        return pubKey.verify(this.unsignedEncoding, this.signature);
    }

    static decode(buffer: Uint8Array, offset: number): [GroupInfo, number] {
        const [
            [
                groupId, epoch, treeHash, confirmedTranscriptHash, extensions,
                confirmationTag, signerIndex,
            ],
            offset1,
        ] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeUint64,
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeVector(Extension.decode, 4),
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeUint32,
            ],
            buffer, offset,
        )
        const [[signature], offset2] = tlspl.decode(
            [tlspl.decodeVariableOpaque(2)], buffer, offset1,
        )
        return [
            new GroupInfo(
                groupId, epoch, treeHash, confirmedTranscriptHash, extensions,
                confirmationTag, signerIndex, buffer.subarray(offset, offset1),
                signature,
            ),
            offset2,
        ];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.groupId, 1),
            tlspl.uint64(this.epoch),
            tlspl.variableOpaque(this.treeHash, 1),
            tlspl.variableOpaque(this.confirmedTranscriptHash, 1),
            tlspl.vector(this.extensions.map(ext => ext.encoder), 4),
            tlspl.variableOpaque(this.confirmationTag, 1),
            tlspl.uint32(this.signerIndex),
            tlspl.variableOpaque(this.signature, 2),
        ]);
    }
}

export class GroupSecrets {
    constructor(
        readonly joinerSecret: Uint8Array,
        readonly pathSecret?: Uint8Array | undefined,
        // readonly psks?: PreSharedKeyID[], // FIXME:
    ) {}

    static decode(buffer: Uint8Array, offset: number): [GroupSecrets, number] {
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[joinerSecret, pathSecret, ], offset1] = tlspl.decode(
            [
                tlspl.decodeVariableOpaque(1),
                tlspl.decodeOptional(tlspl.decodeVariableOpaque(1)),
                tlspl.decodeUint8, // FIXME: decodeOptional(decodeVector(PrSharedKeyID, 2))
            ],
            buffer, offset,
        );
        return [new GroupSecrets(joinerSecret, pathSecret), offset1];
    }
    get encoder(): tlspl.Encoder {
        const fields = [tlspl.variableOpaque(this.joinerSecret, 1)];
        if (this.pathSecret === undefined) {
            fields.push(tlspl.uint8(0));
        } else {
            fields.push(tlspl.uint8(1));
            fields.push(tlspl.variableOpaque(this.pathSecret, 1));
        }
        fields.push(tlspl.uint8(0)); // FIXME: psks
        return tlspl.struct(fields);
    }
}

export class EncryptedGroupSecrets {
    constructor(
        readonly keyPackageHash: Uint8Array,
        readonly encryptedGroupSecrets: HPKECiphertext,
    ) {}

    static decode(buffer: Uint8Array, offset: number): [EncryptedGroupSecrets, number] {
        const [[keyPackageHash, encryptedGroupSecrets], offset1] = tlspl.decode(
            [tlspl.decodeVariableOpaque(1), HPKECiphertext.decode],
            buffer, offset,
        );
        return [new EncryptedGroupSecrets(keyPackageHash, encryptedGroupSecrets), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.variableOpaque(this.keyPackageHash, 1),
            this.encryptedGroupSecrets.encoder,
        ]);
    }
}

export class Welcome {
    constructor(
        readonly cipherSuite: CipherSuite,
        readonly secrets: EncryptedGroupSecrets[],
        readonly encryptedGroupInfo: Uint8Array,
    ) {}

    static decode(buffer: Uint8Array, offset: number): [Welcome, number] {
        const [[cipherSuiteId, secrets, encryptedGroupInfo], offset1] = tlspl.decode(
            [
                tlspl.decodeUint16,
                tlspl.decodeVector(EncryptedGroupSecrets.decode, 4),
                tlspl.decodeVariableOpaque(4),
            ],
            buffer, offset,
        );
        const cipherSuite = cipherSuiteById[cipherSuiteId];
        if (!cipherSuite) {
            throw new Error("Unknown ciphersuite");
        }
        return [new Welcome(cipherSuite, secrets, encryptedGroupInfo), offset1];
    }
    get encoder(): tlspl.Encoder {
        return tlspl.struct([
            tlspl.uint16(this.cipherSuite.id),
            tlspl.vector(this.secrets.map(x => x.encoder), 4),
            tlspl.variableOpaque(this.encryptedGroupInfo, 4),
        ]);
    }

    static async create(
        cipherSuite: CipherSuite,
        joinerSecret: Uint8Array,
        groupInfo: GroupInfo,
        recipients: {keyPackage: KeyPackage, pathSecret?: Uint8Array}[], // FIXME: psks
    ): Promise<Welcome> {
        const hpke = cipherSuite.hpke;
        // FIXME: make sure all recipients are using the same ciphersuite
        const secrets: EncryptedGroupSecrets[] = await Promise.all(
            recipients.map(async ({keyPackage, pathSecret}) => {
                const kpHash = await keyPackage.hash();
                const groupSecrets = new GroupSecrets(joinerSecret, pathSecret);
                const encryptedGroupSecrets = await HPKECiphertext.encrypt(
                    hpke, await keyPackage.getHpkeKey(),
                    EMPTY_BYTE_ARRAY, tlspl.encode([groupSecrets.encoder]),
                );
                return new EncryptedGroupSecrets(kpHash, encryptedGroupSecrets);
            }),
        );

        const [welcomeNonce, welcomeKey] = await Welcome.calculateWelcomeKey(
            cipherSuite, joinerSecret, EMPTY_BYTE_ARRAY,
        );
        const encodedGroupInfo = tlspl.encode([groupInfo.encoder]);
        const encryptedGroupInfo = await hpke.aead.seal(
            welcomeKey, welcomeNonce, EMPTY_BYTE_ARRAY, encodedGroupInfo,
        );

        return new Welcome(cipherSuite, secrets, encryptedGroupInfo);
    }

    static async calculateWelcomeKey(
        cipherSuite: CipherSuite, joinerSecret: Uint8Array, psk: Uint8Array,
    ): Promise<[Uint8Array, Uint8Array]> {
        const hpke = cipherSuite.hpke;
        const memberIkm = await deriveSecret(cipherSuite, joinerSecret, MEMBER);
        const memberSecret = await hpke.kdf.extract(memberIkm, psk);
        const welcomeSecret = await deriveSecret(cipherSuite, memberSecret, WELCOME);

        return await Promise.all([
            hpke.kdf.expand(welcomeSecret, NONCE, hpke.aead.nonceLength),
            hpke.kdf.expand(welcomeSecret, KEY, hpke.aead.keyLength),
        ]);
    }

    async decrypt(
        keyPackages: Record<string, [KeyPackage, KEMPrivateKey]>,
    ): Promise<[GroupSecrets, GroupInfo, string]> {
        const hpke = this.cipherSuite.hpke;
        const kpHashes: [string, Uint8Array][] = await Promise.all(
            // eslint-disable-next-line comma-dangle, array-bracket-spacing
            Object.entries(keyPackages).map(async ([id, [keyPackage, ]]): Promise<[string, Uint8Array]> => {
                return [id, await keyPackage.hash()];
            }),
        );
        let keyId;
        const secrets = this.secrets.find((secret) => {
            for (const [id, kpHash] of kpHashes) {
                if (eqUint8Array(secret.keyPackageHash, kpHash)) {
                    keyId = id;
                    return true;
                }
            }
            return false;
        });
        if (secrets === undefined) {
            throw new Error("Not encrypted for our key package");
        }
        const encodedGroupSecrets = await secrets.encryptedGroupSecrets.decrypt(
            this.cipherSuite.hpke, keyPackages[keyId][1], EMPTY_BYTE_ARRAY,
        );
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [groupSecrets, ] = GroupSecrets.decode(encodedGroupSecrets, 0);
        const [welcomeNonce, welcomeKey] = await Welcome.calculateWelcomeKey(
            this.cipherSuite, groupSecrets.joinerSecret, EMPTY_BYTE_ARRAY,
        )
        const encodedGroupInfo = await hpke.aead.open(
            welcomeKey, welcomeNonce, EMPTY_BYTE_ARRAY, this.encryptedGroupInfo,
        )
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [groupInfo, ] = GroupInfo.decode(encodedGroupInfo, 0);

        return [groupSecrets, groupInfo, keyId];
    }
}
