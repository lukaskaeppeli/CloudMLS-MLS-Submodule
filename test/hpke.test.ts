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

import {p256HkdfSha256, x25519HkdfSha256} from "../src/hpke/dhkem";
import {p256HkdfSha256Aes128Gcm, x25519HkdfSha256Aes128Gcm} from "../src/hpke";
import {hexToUint8Array} from "../src/util";
import {EMPTY_BYTE_ARRAY} from "../src/constants";

describe("HPKE", () => {
    describe("DHKEM(X25519,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM", () => {
        it("Passes the base test vector", async () => {
            // https://tools.ietf.org/html/draft-irtf-cfrg-hpke-07#appendix-A.1.1
            const info = hexToUint8Array("4f6465206f6e2061204772656369616e2055726e");

            const ikmE = hexToUint8Array(
                "6305de86b3cec022fae6f2f2d2951f0f90c8662112124fd62f17e0a99bdbd08e",
            );
            const [skE, pkE] = await x25519HkdfSha256.deriveKeyPair(ikmE);
            // the key stores the clamped value, so it won't match
            //expect(await skE.serialize()).toEqual(hexToUint8Array(
            //    "6cee2e2755790708a2a1be22667883a5e3f9ec52810404a0d889a0ed3e28de00",
            //));
            expect(await pkE.serialize()).toEqual(hexToUint8Array(
                "950897e0d37a8bdb0f2153edf5fa580a64b399c39fbb3d014f80983352a63617",
            ));
            const ikmR = hexToUint8Array(
                "6d9014e4609687b0a3670a22f2a14eac5ae6ad8c0beb62fb3ecb13dc8ebf5e06",
            );
            const [skR, pkR] = await x25519HkdfSha256.deriveKeyPair(ikmR);
            //expect(await skR.serialize()).toEqual(hexToUint8Array(
            //    "ecaf25b8485bcf40b9f013dbb96a6230f25733b8435bba0997a1dedbc7f78806"
            //))
            expect(await pkR.serialize()).toEqual(hexToUint8Array(
                "a5912b20892e36905bac635267e2353d58f8cc7525271a2bf57b9c48d2ec2c07",
            ));

            const [sharedSecret, ] = await pkR.encapsulate(ikmE);
            expect(sharedSecret).toEqual(hexToUint8Array(
                "799b7b9a6a070e77ee9b9a2032f6624b273b532809c60200eba17ac3baf69a00",
            ));

            const [enc, context] = await x25519HkdfSha256Aes128Gcm.setupBaseS(pkR, info, ikmE);
            expect(enc).toEqual(hexToUint8Array(
                "950897e0d37a8bdb0f2153edf5fa580a64b399c39fbb3d014f80983352a63617",
            ));
            expect(context.key).toEqual(hexToUint8Array(
                "e20cee1bf5392ad2d3a442e231f187ae",
            ));
            expect(context.nonce).toEqual(hexToUint8Array(
                "5d99b2f03c452f7a9441933a",
            ));
            expect(context.exporterSecret).toEqual(hexToUint8Array(
                "00c3cdacab28e981cc907d12e4f55f0aacae261dbb4eb610447a6bc431bfe2aa",
            ));

            // A.1.1.1 Encryptions
            const plaintext = hexToUint8Array("4265617574792069732074727574682c20747275746820626561757479");

            const ciphertext0 = await context.seal(
                hexToUint8Array("436f756e742d30"),
                plaintext,
            );
            expect(ciphertext0).toEqual(hexToUint8Array(
                "9418f1ae06eddc43aa911032aed4a951754ee2286a786733761857f8d96a7ec8d852da93bc5eeab49623344aba",
            ));
            expect(context.sequence).toEqual(hexToUint8Array(
                "000000000000000000000001",
            ));
            context.sequence.fill(0); // reset sequence so we can decrypt
            expect(await context.open(
                hexToUint8Array("436f756e742d30"),
                ciphertext0,
            )).toEqual(plaintext);

            const ciphertext1 = await context.seal(
                hexToUint8Array("436f756e742d31"),
                plaintext,
            );
            expect(ciphertext1).toEqual(hexToUint8Array(
                "74d69c61899b9158bb50e95d92fbad106f612ea67c61b3c4bef65c8bf3dc18e17bf41ec4c408688aae58358d0e",
            ));
            expect(context.sequence).toEqual(hexToUint8Array(
                "000000000000000000000002",
            ));
            context.sequence.fill(0);
            context.sequence[11] = 1;
            expect(await context.open(
                hexToUint8Array("436f756e742d31"),
                ciphertext1,
            )).toEqual(plaintext);

            // FIXME: add the other cases

            // A.1.1.2. Exported Values
            const exported1 = await context.export(EMPTY_BYTE_ARRAY, 32);
            expect(exported1).toEqual(hexToUint8Array(
                "be82c06bd83fd6edd74385de5a70859b9e03def4c7bb224a10cfae86087f8a25",
            ));

            const exported2 = await context.export(new Uint8Array(1), 32);
            expect(exported2).toEqual(hexToUint8Array(
                "82cbfd3c2b2db75e2311d457e569cf12b6387eb4309bca8e77adb2f2b599fc85",
            ));

            const exported3 = await context.export(
                hexToUint8Array("54657374436f6e74657874"), 32,
            );
            expect(exported3).toEqual(hexToUint8Array(
                "c8387c1e6ec4f026c7f3577e3f29df51f46161295eec84c4f64a9174f7b64e4f",
            ));
        });
    });

    describe("DHKEM(P256,HKDF-SHA256)", () => {
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

    describe("DHKEM(P256,HKDF-SHA256)/HKDF-SHA256/AES-128-GCM", () => {
        // FIXME: test against test vectors
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
