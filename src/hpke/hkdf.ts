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

/** KDF operations using HKDF-SHA*
 */

import {KDF} from "./base";
import {concatUint8Array} from "../util";

const subtle = window.crypto.subtle;

function makeHKDF(name: string, size: number, blockSize: number, id: number): KDF {
    let zeroKey; // a key consisting of blockSize 0's, which is the default salt
    return {
        async extract(salt: Uint8Array | undefined, ikm: Uint8Array): Promise<Uint8Array> {
            let key;
            // importKey doesn't like a 0-byte length, so if it's size 0,
            // expand it to an all-zero array, because that's what HMAC will do
            // anyways
            if (salt === undefined || salt.length === 0) {
                if (!zeroKey) {
                    salt = new Uint8Array(blockSize);
                    zeroKey = await subtle.importKey(
                        "raw", salt, {name: "HMAC", hash: name, length: salt.byteLength * 8},
                        false, ["sign"],
                    );
                }
                key = zeroKey;
            } else {
                key = await subtle.importKey(
                    "raw", salt, {name: "HMAC", hash: name, length: salt.byteLength * 8},
                    false, ["sign"],
                );
            }
            return new Uint8Array(await subtle.sign("HMAC", key, ikm));
        },

        async expand(prk: Uint8Array, info: Uint8Array | undefined, length: number): Promise<Uint8Array> {
            if (info === undefined) {
                info = new Uint8Array(0);
            }
            const ret = new Uint8Array(length);
            const key = await subtle.importKey(
                "raw", prk, {name: "HMAC", hash: name, length: info.byteLength * 8},
                false, ["sign"],
            );
            let chunk: Uint8Array = new Uint8Array(0);
            for (let [pos, i] = [0, 0]; pos < length; pos += size, i++) {
                chunk = new Uint8Array(
                    await subtle.sign(
                        "HMAC", key,
                        concatUint8Array([chunk, info, Uint8Array.from([i + 1])]),
                    ),
                );
                if (pos + size > length) {
                    ret.set(chunk.subarray(0, length - pos), size * i);
                } else {
                    ret.set(chunk, size * i);
                }
            }
            return ret;
        },

        extractLength: size,
        hashLength: size,

        id: id,
    };
}

export const hkdfSha256: KDF = makeHKDF("SHA-256", 32, 64, 0x0001);
export const hkdfSha384: KDF = makeHKDF("SHA-384", 48, 128, 0x0002);
export const hkdfSha512: KDF = makeHKDF("SHA-512", 64, 128, 0x0003);
