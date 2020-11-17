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
    AUTHENTICATION,
    CONFIRM,
    EMPTY_BYTE_ARRAY,
    ENCRYPTION,
    EPOCH,
    EXPORTER,
    EXTERNAL,
    INIT,
    MEMBER,
    MEMBERSHIP,
    MLS10,
    RESUMPTION,
    SENDER_DATA,
    WELCOME,
} from "./constants";
import {HPKE} from "./hpke/base";
import * as tlspl from "./tlspl";

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
    if (psk === undefined) {
        psk = EMPTY_BYTE_ARRAY; // FIXME: ???
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
