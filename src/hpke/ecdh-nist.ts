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

import {DH, DHPublicKey, DHPrivateKey} from "./base"

const subtle = window.crypto.subtle;

// 4.1.  DH-Based KEM

function makeDH(
    name: string,
    publicKeyLength: number,
    privateKeyLength: number,
    secretLength: number,
): DH {
    class PublicKey extends DHPublicKey {
        constructor(private readonly key: CryptoKey) { super(); }
        async dh(privKey: DHPrivateKey): Promise<Uint8Array> {
            if (privKey instanceof PrivateKey) {
                return new Uint8Array(await subtle.deriveBits(
                    {name: "ECDH", public: this.key}, privKey.keyPair.privateKey, secretLength,
                ));
            } else {
                throw new Error("Incompatible private key");
            }
        }
        async serialize(): Promise<Uint8Array> {
            return new Uint8Array(await subtle.exportKey("raw", this.key));
        }
    }

    class PrivateKey extends DHPrivateKey {
        constructor(readonly keyPair: CryptoKeyPair) { super(); }
    }

    return {
        async generateKeyPair(): Promise<[DHPrivateKey, DHPublicKey]> {
            const keyPair: CryptoKeyPair = await subtle.generateKey(
                {name: "ECDH", namedCurve: name}, true, ["deriveBits"],
            );
            return [new PrivateKey(keyPair), new PublicKey(keyPair.publicKey)];
        },

        async deriveKeyPair(ikm: Uint8Array): Promise<[DHPrivateKey, DHPublicKey]> {
            // FIXME: this is wrong
            const keyPair: CryptoKeyPair = await subtle.generateKey(
                {name: "ECDH", namedCurve: name}, true, ["deriveBits"],
            );
            return [new PrivateKey(keyPair), new PublicKey(keyPair.publicKey)];
        },

        async deserialize(enc: Uint8Array): Promise<DHPublicKey> {
            const pubKey: CryptoKey = await subtle.importKey(
                "raw", enc,
                {name: "ECDH", namedCurve: name}, true, ["deriveBits"],
            );
            return new PublicKey(pubKey);
        },

        publicKeyLength: publicKeyLength,
        privateKeyLength: privateKeyLength,
        secretLength: secretLength,
    };
}

export const p256: DH = makeDH("P-256", 65, 32, 32);
export const p384: DH = makeDH("P-384", 97, 48, 48);
export const p521: DH = makeDH("P-521", 133, 66, 64);
