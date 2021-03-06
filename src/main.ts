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

import {p256} from "./hpke/ecdh-nist";
import {hkdfSha256} from "./hpke/hkdf";
import {p256HkdfSha256} from "./hpke/dhkem";
import {aes128Gcm, aes256Gcm} from "./hpke/aes"

export const kem = {
    p256HkdfSha256,
};

export const kdf = {
    hkdfSha256,
};

export const aead = {
    aes128Gcm,
    aes256Gcm,
};

export const dh = {
    p256,
};
