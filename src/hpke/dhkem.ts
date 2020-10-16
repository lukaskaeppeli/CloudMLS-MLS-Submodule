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

// 4.1.  DH-Based KEM

/** DHKEM methods, build from DH groups and KDFs */

import {KEM, makeDHKEM} from "./base";
import {hkdfSha256, hkdfSha384, hkdfSha512} from "./hkdf";
import {p256, p384, p521} from "./ecdh-nist";

export const p256HkdfSha256: KEM = makeDHKEM(p256, hkdfSha256, 0x0010);
export const p384HkdfSha384: KEM = makeDHKEM(p384, hkdfSha384, 0x0011);
export const p521HkdfSha512: KEM = makeDHKEM(p521, hkdfSha512, 0x0012);
