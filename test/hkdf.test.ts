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

import {hkdfSha256, hkdfSha384, hkdfSha512} from "../src/hpke/hkdf";
import {labeledExtract, labeledExpand} from "../src/hpke/base";
import {hexToUint8Array, stringToUint8Array} from "../src/util";

describe("HKDF", () => {
    // https://tools.ietf.org/html/rfc5869#appendix-A.1
    const expandSize = 42;
    const ikm = hexToUint8Array("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    const salt = hexToUint8Array("000102030405060708090a0b0c");
    const info = hexToUint8Array("f0f1f2f3f4f5f6f7f8f9");

    // from lib/hpke/test/kdf.cpp from mlspp
    const label = stringToUint8Array("test");
    const cases = [
        {
            name: "SHA-256",
            kdf: hkdfSha256,
            suiteId: hexToUint8Array("4b44460001"),
            extracted: hexToUint8Array(
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
            ),
            expanded: hexToUint8Array(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5b" +
                    "f34007208d5b887185865",
            ),
            labeledExtracted: hexToUint8Array(
                "b3ff2930e482ac10e3b256863288c2b0ebe3c5b999462b281e7119e1e05d8a55",
            ),
            labeledExpanded: hexToUint8Array(
                "c38019a12154353cb7659d003c55853856a29953234508729909a4144c1f21f" +
                "000319302ab20b381e321",
            ),
        },
        {
            name: "SHA-384",
            kdf: hkdfSha384,
            suiteId: hexToUint8Array("4b44460002"),
            extracted: hexToUint8Array(
                "704b39990779ce1dc548052c7dc39f303570dd13fb39f7acc564680bef80e8d" +
                "ec70ee9a7e1f3e293ef68eceb072a5ade",
            ),
            expanded: hexToUint8Array(
                "9b5097a86038b805309076a44b3a9f38063e25b516dcbf369f394cfab43685f" +
                "748b6457763e4f0204fc5",
            ),
            labeledExtracted: hexToUint8Array(
                "aa52397877bbae9d7fa36dd7e4dfc387145954dfdffbfd5d81570a067095fa1" +
                "7bb1f90cf1805f4f132f2e2759a6d1bef",
            ),
            labeledExpanded: hexToUint8Array(
                "61f6f019651351cb09135fe66b0b078f6c421fb1a138d4f050e70d1e013e4aa" +
                "c77d83cee050bc5597d54",
            ),
        },
        {
            name: "SHA-512",
            kdf: hkdfSha512,
            suiteId: hexToUint8Array("4b44460003"),
            extracted: hexToUint8Array(
                "665799823737ded04a88e47e54a5890bb2c3d247c7a4254a8e61350723590a26c36238" +
                "127d8661b88cf80ef802d57e2f7cebcf1e00e083848be19929c61b4237",
            ),
            expanded: hexToUint8Array(
                "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579" +
                "338da362cb8d9f925d7cb",
            ),
            labeledExtracted: hexToUint8Array(
                "06feddff04160100e3587a5b652af12d06f128b4cb9cb39a44526acf5c9bc9e8bf3b0c" +
                "ef579c969a2beb54b070797bb920d6b85561036397f6e163c9cd12b210",
            ),
            labeledExpanded: hexToUint8Array(
                "0ec647b801d616313ccb45cda27d1f7e50eb2c9d03dffc4c3bb0a73a15030d9" +
                "8a7ba09de1973304c1742",
            ),
        },
    ];

    for (const c of cases) {
        describe(c.name, () => {
            it("should HKDF", async () => {
                // check against test vectors
                expect(await c.kdf.extract(salt, ikm)).toEqual(c.extracted);
                expect(await c.kdf.expand(c.extracted, info, expandSize))
                    .toEqual(c.expanded);
                expect(await labeledExtract(c.kdf, c.suiteId, salt, label, ikm))
                    .toEqual(c.labeledExtracted);
                expect(await labeledExpand(c.kdf, c.suiteId, c.labeledExtracted, label, info, expandSize))
                    .toEqual(c.labeledExpanded);

                // check with empty salt against WebCrypto
                const hkdfKey = await window.crypto.subtle.importKey(
                    "raw", ikm, "HKDF", false, ["deriveBits"],
                );
                expect(await c.kdf.expand(
                    await c.kdf.extract(undefined, ikm),
                    info, expandSize,
                )).toEqual(new Uint8Array(await window.crypto.subtle.deriveBits(
                    {name: "HKDF", hash: c.name, salt: new Uint8Array(), info: info},
                    hkdfKey, expandSize * 8,
                )));
                expect(await c.kdf.expand(
                    await c.kdf.extract(new Uint8Array(), ikm),
                    info, expandSize,
                )).toEqual(new Uint8Array(await window.crypto.subtle.deriveBits(
                    {name: "HKDF", hash: c.name, salt: new Uint8Array(), info: info},
                    hkdfKey, expandSize * 8,
                )));
            });
        });
    }
});
