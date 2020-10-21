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

/** HPKE (Hybrid Public Key Encryption) operations
 * https://tools.ietf.org/html/draft-irtf-cfrg-hpke-05
 */

import {p256, p384, p521} from "./hpke/ecdh-nist";
import {x25519} from "./hpke/ecdh-x";
import {hkdfSha256, hkdfSha384, hkdfSha512} from "./hpke/hkdf";
import {
    p256HkdfSha256,
    p384HkdfSha384,
    p521HkdfSha512,
    x25519HkdfSha256,
} from "./hpke/dhkem";
import {aes128Gcm, aes256Gcm} from "./hpke/aes";
import {HPKE} from "./hpke/base";

export const kem = {
    p256HkdfSha256,
    p384HkdfSha384,
    p521HkdfSha512,
    x25519HkdfSha256,
};

export const kdf = {
    hkdfSha256,
    hkdfSha384,
    hkdfSha512,
};

export const aead = {
    aes128Gcm,
    aes256Gcm,
};

export const dh = {
    p256,
    p384,
    p521,
};

export const p256HkdfSha256Aes128Gcm = new HPKE(p256HkdfSha256, hkdfSha256, aes128Gcm);
export const x25519HkdfSha256Aes128Gcm = new HPKE(x25519HkdfSha256, hkdfSha256, aes128Gcm);
