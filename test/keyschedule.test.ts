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

import {x25519HkdfSha256Aes128Gcm} from "../src/hpke";
import {SecretTree, HashRatchet} from "../src/keyschedule";

describe("secret tree", () => {
    it("should derive all leaf ratchets", async () => {
        const secretTree = new SecretTree(
            x25519HkdfSha256Aes128Gcm,
            new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength),
            5,
        );
        // we should be able to derive all the secrets
        await secretTree.getRatchetsForLeaf(0);
        await secretTree.getRatchetsForLeaf(4);
        await secretTree.getRatchetsForLeaf(3);
        await secretTree.getRatchetsForLeaf(1);
        await secretTree.getRatchetsForLeaf(2);

        // trying to derive them again should fail
        await expect(secretTree.getRatchetsForLeaf(0)).rejects.toThrow();
        await expect(secretTree.getRatchetsForLeaf(1)).rejects.toThrow();
        await expect(secretTree.getRatchetsForLeaf(2)).rejects.toThrow();
        await expect(secretTree.getRatchetsForLeaf(3)).rejects.toThrow();
        await expect(secretTree.getRatchetsForLeaf(4)).rejects.toThrow();
    });
    it("should derive different ratchets", async () => {
        const secretTree = new SecretTree(
            x25519HkdfSha256Aes128Gcm,
            new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength),
            5,
        );
        const [handshake0, application0] = await secretTree.getRatchetsForLeaf(0);
        const [handshake1, application1] = await secretTree.getRatchetsForLeaf(1);
        const [handshake3, application3] = await secretTree.getRatchetsForLeaf(3);
        const [handshake4, application4] = await secretTree.getRatchetsForLeaf(4);
        const [handshake2, application2] = await secretTree.getRatchetsForLeaf(2);

        const [handshake0nonce0, handshake0key0] = await handshake0.getKey(0);
        const [handshake0nonce1, handshake0key1] = await handshake0.getKey(1);
        const [application0nonce0, application0key0] = await application0.getKey(0);
        const [application0nonce1, application0key1] = await application0.getKey(1);
        expect(handshake0nonce0).not.toEqual(handshake0key0);
        expect(handshake0nonce0).not.toEqual(handshake0nonce1);
        expect(handshake0key0).not.toEqual(handshake0key1);
        expect(handshake0nonce0).not.toEqual(application0nonce0);
        expect(application0nonce0).not.toEqual(application0key0);
        expect(application0nonce0).not.toEqual(application0nonce1);
        expect(application0key0).not.toEqual(application0key1);

        const [handshake1nonce0, handshake1key0] = await handshake1.getKey(0);
        expect(handshake0nonce0).not.toEqual(handshake1nonce0);
        expect(handshake0key0).not.toEqual(handshake1key0);

        const [handshake2nonce0, handshake2key0] = await handshake2.getKey(0);
        expect(handshake0nonce0).not.toEqual(handshake2nonce0);
        expect(handshake0key0).not.toEqual(handshake2key0);
        expect(handshake1nonce0).not.toEqual(handshake2nonce0);
        expect(handshake1key0).not.toEqual(handshake2key0);

        const [handshake3nonce0, handshake3key0] = await handshake3.getKey(0);
        expect(handshake0nonce0).not.toEqual(handshake3nonce0);
        expect(handshake0key0).not.toEqual(handshake3key0);
        expect(handshake1nonce0).not.toEqual(handshake3nonce0);
        expect(handshake1key0).not.toEqual(handshake3key0);
        expect(handshake2nonce0).not.toEqual(handshake3nonce0);
        expect(handshake2key0).not.toEqual(handshake3key0);

        const [handshake4nonce0, handshake4key0] = await handshake4.getKey(0);
        expect(handshake0nonce0).not.toEqual(handshake4nonce0);
        expect(handshake0key0).not.toEqual(handshake4key0);
        expect(handshake1nonce0).not.toEqual(handshake4nonce0);
        expect(handshake1key0).not.toEqual(handshake4key0);
        expect(handshake2nonce0).not.toEqual(handshake4nonce0);
        expect(handshake2key0).not.toEqual(handshake4key0);
        expect(handshake3nonce0).not.toEqual(handshake4nonce0);
        expect(handshake3key0).not.toEqual(handshake4key0);
    });
    it("should handle out-of-order messages", async () => {
        const hashRatchet1 = new HashRatchet(
            x25519HkdfSha256Aes128Gcm, 0,
            new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength),
        );
        const hashRatchet2 = new HashRatchet(
            x25519HkdfSha256Aes128Gcm, 0,
            new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength),
        );

        const key1g0 = await hashRatchet1.getKey(0);
        const key1g1 = await hashRatchet1.getKey(1);
        const key1g2 = await hashRatchet1.getKey(2);
        const key1g3 = await hashRatchet1.getKey(3);
        const key1g4 = await hashRatchet1.getKey(4);

        // we should get the same results no matter what order it's derived in
        const key2g3 = await hashRatchet2.getKey(3);
        const key2g1 = await hashRatchet2.getKey(1);
        const key2g0 = await hashRatchet2.getKey(0);
        const key2g4 = await hashRatchet2.getKey(4);
        const key2g2 = await hashRatchet2.getKey(2);

        expect(key1g0).toEqual(key2g0);
        expect(key1g1).toEqual(key2g1);
        expect(key1g2).toEqual(key2g2);
        expect(key1g3).toEqual(key2g3);
        expect(key1g4).toEqual(key2g4);

        // trying to re-derive any of them should thrown an error
        await expect(hashRatchet1.getKey(0)).rejects.toThrow();
        await expect(hashRatchet1.getKey(1)).rejects.toThrow();
        await expect(hashRatchet1.getKey(2)).rejects.toThrow();
        await expect(hashRatchet1.getKey(3)).rejects.toThrow();
        await expect(hashRatchet1.getKey(4)).rejects.toThrow();
        await expect(hashRatchet2.getKey(0)).rejects.toThrow();
        await expect(hashRatchet2.getKey(1)).rejects.toThrow();
        await expect(hashRatchet2.getKey(2)).rejects.toThrow();
        await expect(hashRatchet2.getKey(3)).rejects.toThrow();
        await expect(hashRatchet2.getKey(4)).rejects.toThrow();
    });
});
