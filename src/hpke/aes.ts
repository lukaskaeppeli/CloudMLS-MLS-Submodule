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

/** AEAD using AES-GCM */

import {AEAD} from "./base";

const subtle = window.crypto.subtle;

export const aes128Gcm: AEAD = {
    async seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
        const k: CryptoKey = await subtle.importKey(
            "raw", key, "AES-GCM", false, ["encrypt"],
        );
        return new Uint8Array(
            await subtle.encrypt(
                {name: "AES-GCM", iv: nonce, additionalData: aad},
                k, pt,
            ),
        );
    },

    async open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
        const k: CryptoKey = await subtle.importKey(
            "raw", key, "AES-GCM", false, ["decrypt"],
        );
        return new Uint8Array(
            await subtle.decrypt(
                {name: "AES-GCM", iv: nonce, additionalData: aad},
                k, ct,
            ),
        );
    },

    keyLength: 16,
    nonceLength: 96,

    id: 0x0001,
};

export const aes256Gcm: AEAD = {
    async seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
        const k: CryptoKey = await subtle.importKey(
            "raw", key, "AES-GCM", false, ["encrypt"],
        );
        return new Uint8Array(
            await subtle.encrypt(
                {name: "AES-GCM", iv: nonce, additionalData: aad},
                k, pt,
            ),
        );
    },

    async open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
        const k: CryptoKey = await subtle.importKey(
            "raw", key, "AES-GCM", false, ["decrypt"],
        );
        return new Uint8Array(
            await subtle.decrypt(
                {name: "AES-GCM", iv: nonce, additionalData: aad},
                k, ct,
            ),
        );
    },

    keyLength: 32,
    nonceLength: 96,

    id: 0x0002,
};
