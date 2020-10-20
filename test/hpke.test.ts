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

import {p256HkdfSha256} from "../src/hpke/dhkem";
import {p256HkdfSha256Aes128Gcm} from "../src/hpke";

describe("HPKE", () => {
    describe("P256-HKDF-SHA256", () => {
        it("encapsulates and decapsulates", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const [key, enc] = await publicKey.encapsulate();

            expect(await privateKey.decapsulate(enc)).toEqual(key);
        });

        it("encapsulates and decapsulates with authentication", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();
            const [skS, pkS] = await p256HkdfSha256.generateKeyPair();

            const [key, enc] = await publicKey.authEncapsulate(skS);

            expect(await privateKey.authDecapsulate(enc, pkS)).toEqual(key);
        });
    });

    describe("P256-HKDF-SHA256/HKDF-SHA256/AES-128-GCM", () => {
        it("creates base context", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);

            const [enc, baseS] = await p256HkdfSha256Aes128Gcm.setupBaseS(
                publicKey, info,
            );

            const baseR = await p256HkdfSha256Aes128Gcm.setupBaseR(
                enc, privateKey, info,
            );

            expect(baseS).toEqual(baseR);
        });

        it("creates PSK context", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const psk = Uint8Array.from([0, 1, 2]);
            const pskId = Uint8Array.from([3, 4, 5]);

            const [enc, baseS] = await p256HkdfSha256Aes128Gcm.setupPskS(
                publicKey, info, psk, pskId,
            );

            const baseR = await p256HkdfSha256Aes128Gcm.setupPskR(
                enc, privateKey, info, psk, pskId,
            );

            expect(baseS).toEqual(baseR);
        });

        it("creates authenticated context", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const [skS, pkS] = await p256HkdfSha256.generateKeyPair();

            const [enc, baseS] = await p256HkdfSha256Aes128Gcm.setupAuthS(
                publicKey, info, skS,
            );

            const baseR = await p256HkdfSha256Aes128Gcm.setupAuthR(
                enc, privateKey, info, pkS,
            );

            expect(baseS).toEqual(baseR);
        });

        it("creates authenticated context with PSK", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const [skS, pkS] = await p256HkdfSha256.generateKeyPair();
            const psk = Uint8Array.from([0, 1, 2]);
            const pskId = Uint8Array.from([3, 4, 5]);

            const [enc, baseS] = await p256HkdfSha256Aes128Gcm.setupAuthPskS(
                publicKey, info, psk, pskId, skS,
            );

            const baseR = await p256HkdfSha256Aes128Gcm.setupAuthPskR(
                enc, privateKey, info, psk, pskId, pkS,
            );

            expect(baseS).toEqual(baseR);
        });

        it("exports secrets", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);

            const [enc, baseS] = await p256HkdfSha256Aes128Gcm.setupBaseS(
                publicKey, info,
            );

            const baseR = await p256HkdfSha256Aes128Gcm.setupBaseR(
                enc, privateKey, info,
            );

            const exporterContext = Uint8Array.from([4, 5, 6]);

            const secret = await baseS.export(exporterContext, 10);
            expect(await baseR.export(exporterContext, 10)).toEqual(secret);
        });

        it("encrypts and decrypts", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const aad = Uint8Array.from([4, 5, 6]);
            const pt = Uint8Array.from([7, 8, 9]);

            const [enc, ct] = await p256HkdfSha256Aes128Gcm.sealBase(
                publicKey, info, aad, pt,
            );

            expect(await p256HkdfSha256Aes128Gcm.openBase(
                enc, privateKey, info, aad, ct,
            )).toEqual(pt);

            expect(async () => {
                await p256HkdfSha256Aes128Gcm.openBase(
                    enc, privateKey, info, Uint8Array.from([6, 5, 4]), ct,
                );
            }).rejects.toThrow();
        });

        it("encrypts and decrypts with PSK", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const aad = Uint8Array.from([4, 5, 6]);
            const pt = Uint8Array.from([7, 8, 9]);
            const psk = Uint8Array.from([0, 1, 2]);
            const pskId = Uint8Array.from([3, 4, 5]);

            const [enc, ct] = await p256HkdfSha256Aes128Gcm.sealPsk(
                publicKey, info, aad, pt, psk, pskId,
            );

            expect(await p256HkdfSha256Aes128Gcm.openPsk(
                enc, privateKey, info, aad, ct, psk, pskId,
            )).toEqual(pt);

            expect(async () => {
                await p256HkdfSha256Aes128Gcm.openPsk(
                    enc, privateKey, info, Uint8Array.from([6, 5, 4]), ct, psk, pskId,
                );
            }).rejects.toThrow();
        });

        it("encrypts and decrypts with authentication", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const [skS, pkS] = await p256HkdfSha256.generateKeyPair();
            const aad = Uint8Array.from([4, 5, 6]);
            const pt = Uint8Array.from([7, 8, 9]);

            const [enc, ct] = await p256HkdfSha256Aes128Gcm.sealAuth(
                publicKey, info, aad, pt, skS,
            );

            expect(await p256HkdfSha256Aes128Gcm.openAuth(
                enc, privateKey, info, aad, ct, pkS,
            )).toEqual(pt);

            expect(async () => {
                await p256HkdfSha256Aes128Gcm.openAuth(
                    enc, privateKey, info, Uint8Array.from([6, 5, 4]), ct, pkS,
                );
            }).rejects.toThrow();
        });

        it("encrypts and decrypts with PSK and authentication", async () => {
            const [privateKey, publicKey] = await p256HkdfSha256.generateKeyPair();

            const info = Uint8Array.from([1, 2, 3]);
            const [skS, pkS] = await p256HkdfSha256.generateKeyPair();
            const aad = Uint8Array.from([4, 5, 6]);
            const pt = Uint8Array.from([7, 8, 9]);
            const psk = Uint8Array.from([0, 1, 2]);
            const pskId = Uint8Array.from([3, 4, 5]);

            const [enc, ct] = await p256HkdfSha256Aes128Gcm.sealAuthPsk(
                publicKey, info, aad, pt, psk, pskId, skS,
            );

            expect(await p256HkdfSha256Aes128Gcm.openAuthPsk(
                enc, privateKey, info, aad, ct, psk, pskId, pkS,
            )).toEqual(pt);

            expect(async () => {
                await p256HkdfSha256Aes128Gcm.openAuthPsk(
                    enc, privateKey, info, Uint8Array.from([6, 5, 4]), ct, psk, pskId, pkS,
                );
            }).rejects.toThrow();
        });
    });
});
