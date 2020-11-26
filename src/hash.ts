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

const subtle = window.crypto.subtle;

/** Hash functions.  Also define MAC functions since MLS uses hash-based MACs
 */

export interface Hash {
    hash: (data: Uint8Array) => Promise<Uint8Array>;
    mac: (key: Uint8Array, data: Uint8Array) => Promise<Uint8Array>;
    verifyMac: (key: Uint8Array, data: Uint8Array, mac: Uint8Array) => Promise<boolean>;
}

function makeHash(name: string): Hash {
    return {
        async hash(data: Uint8Array): Promise<Uint8Array> {
            return new Uint8Array(await subtle.digest(name, data));
        },
        async mac(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
            const cryptoKey = await subtle.importKey(
                "raw", key, {name: "HMAC", hash: name, length: key.byteLength * 8},
                false, ["sign"],
            );
            return new Uint8Array(await subtle.sign("HMAC", cryptoKey, data));
        },
        async verifyMac(key: Uint8Array, data: Uint8Array, mac: Uint8Array): Promise<boolean> {
            const cryptoKey = await subtle.importKey(
                "raw", key, {name: "HMAC", hash: name, length: key.byteLength * 8},
                false, ["verify"],
            );
            return await subtle.verify("HMAC", cryptoKey, mac, data);
        },
    }
}

export const sha256: Hash = makeHash("SHA-256");

export const sha512: Hash = makeHash("SHA-512");
