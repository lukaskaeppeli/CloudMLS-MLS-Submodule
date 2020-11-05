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

/** ECDH operations using the NIST curves
 */

import {KDF, DH, DHPublicKey, DHPrivateKey, labeledExtract, labeledExpand} from "./base"
import {EMPTY_BYTE_ARRAY, CANDIDATE, DKP_PRK} from "../constants";
import {eqUint8Array, geUint8Array} from "../util";
import {ec as EC} from "elliptic";

// 4.1.  DH-Based KEM

function makeDH(
    name: string,
    publicKeyLength: number,
    privateKeyLength: number,
    secretLength: number,
    bitmask: number,
): DH {
    const ec = new EC(name);
    const zeroKey = new Uint8Array(privateKeyLength);
    const order = ec.n.toArrayLike(Uint8Array, "be", privateKeyLength);

    class PublicKey extends DHPublicKey {
        constructor(private readonly key) { super(); }
        async dh(privKey: DHPrivateKey): Promise<Uint8Array> {
            if (!(privKey instanceof PrivateKey)) {
                throw new Error("Incompatible private key");
            }

            return privKey.keyPair.derive(this.key)
                .toArrayLike(Uint8Array, "be", privateKeyLength);
        }
        async serialize(): Promise<Uint8Array> {
            return Uint8Array.from(this.key.encode());
        }
    }

    class PrivateKey extends DHPrivateKey {
        constructor(readonly keyPair) { super(); }
    }

    return {
        async generateKeyPair(): Promise<[DHPrivateKey, DHPublicKey]> {
            const keyPair = ec.genKeyPair();
            return [new PrivateKey(keyPair), new PublicKey(keyPair.getPublic())];
        },

        // 7.1.2.  DeriveKeyPair
        async deriveKeyPair(
            kdf: KDF, suiteId: Uint8Array, ikm: Uint8Array,
        ): Promise<[DHPrivateKey, DHPublicKey]> {
            const dkpPrk = await labeledExtract(
                kdf, suiteId, EMPTY_BYTE_ARRAY, DKP_PRK, ikm,
            );
            let sk: Uint8Array;
            let counter = 0;
            do {
                if (counter++ > 255) {
                    throw new Error("Error deriving key pair");
                }
                sk = await labeledExpand(
                    kdf, suiteId,
                    dkpPrk, CANDIDATE, Uint8Array.from([counter]), privateKeyLength,
                );
                sk[0] &= bitmask;
            } while (eqUint8Array(sk, zeroKey) || geUint8Array(sk, order));

            const keyPair = ec.keyFromPrivate(sk);
            return [new PrivateKey(keyPair), new PublicKey(keyPair.getPublic())];
        },

        async deserialize(enc: Uint8Array): Promise<DHPublicKey> {
            return new PublicKey(ec.keyFromPublic(enc).getPublic());
        },

        publicKeyLength: publicKeyLength,
        privateKeyLength: privateKeyLength,
        secretLength: secretLength,
    };
}

export const p256: DH = makeDH("p256", 65, 32, 32, 0xff);
export const p384: DH = makeDH("p384", 97, 48, 48, 0xff);
export const p521: DH = makeDH("p521", 133, 66, 64, 0x01);
