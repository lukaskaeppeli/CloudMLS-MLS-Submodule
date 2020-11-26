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

import {SenderType, EMPTY_BYTE_ARRAY} from "../src/constants";
import {x25519HkdfSha256Aes128Gcm} from "../src/hpke";
import {sha256} from "../src/hash";
import {Sender, MLSPlaintext, MLSCiphertext} from "../src/message";
import {Ed25519} from "../src/signatures";
import {stringToUint8Array} from "../src/util";
import {GroupContext} from "../src/ratchettree";
import {HashRatchet} from "../src/keyschedule";
import * as tlspl from "../src/tlspl";

describe("MLS Plaintext", () => {
    it("should create and verify", async () => {
        const [signingPrivKey, signingPubKey] = await Ed25519.generateKeyPair();
        const groupId = stringToUint8Array("!abc:example.org");
        const epoch = 3;
        const groupContext = new GroupContext(
            groupId, epoch, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, [],
        );
        const authenticatedData = Uint8Array.from([1, 2, 3]);
        const content = Uint8Array.from([4, 5, 6, 7]);
        const membershipKey = new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength);
        window.crypto.getRandomValues(membershipKey);
        const mlsPlaintext = await MLSPlaintext.create(
            sha256,
            groupId,
            epoch,
            new Sender(SenderType.Member, 4),
            authenticatedData,
            content,
            signingPrivKey,
            new Uint8Array(),
            groupContext,
            membershipKey,
        );

        const encodedMlsPlaintext = tlspl.encode([mlsPlaintext.encoder]);

        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedMlsPlaintext], ] = tlspl.decode([MLSPlaintext.decode], encodedMlsPlaintext, 0);

        expect(await decodedMlsPlaintext.verify(sha256, signingPubKey, groupContext, membershipKey)).toBe(true);

        const wrongGroupContext = new GroupContext(
            groupId, epoch + 1, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, [],
        );
        expect(await decodedMlsPlaintext.verify(sha256, signingPubKey, wrongGroupContext, membershipKey)).toBe(false);

        const wrongMembershipKey = new Uint8Array(membershipKey);
        wrongMembershipKey[1] ^= 0xff;
        expect(await decodedMlsPlaintext.verify(sha256, signingPubKey, groupContext, wrongMembershipKey)).toBe(false);
    });
});

describe("MLS Ciphertext", () => {
    it("should encrypt and decrypt", async () => {
        const [signingPrivKey, signingPubKey] = await Ed25519.generateKeyPair();
        const groupId = stringToUint8Array("!abc:example.org");
        const epoch = 3;
        const groupContext = new GroupContext(
            groupId, epoch, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY, [],
        );
        const authenticatedData = Uint8Array.from([1, 2, 3]);
        const content = Uint8Array.from([4, 5, 6, 7]);
        const mlsPlaintext = await MLSPlaintext.create(
            sha256,
            groupId,
            epoch,
            new Sender(SenderType.Member, 4),
            authenticatedData,
            content,
            signingPrivKey,
            new Uint8Array(),
            groupContext,
        );

        const secret = new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength);
        window.crypto.getRandomValues(secret);
        const senderHashRatchet = new HashRatchet(
            x25519HkdfSha256Aes128Gcm, 4, new Uint8Array(secret),
        );
        const senderDataSecret = new Uint8Array(x25519HkdfSha256Aes128Gcm.kdf.extractLength);
        window.crypto.getRandomValues(senderDataSecret);

        const mlsCiphertext = await MLSCiphertext.create(
            x25519HkdfSha256Aes128Gcm,
            mlsPlaintext,
            senderHashRatchet,
            senderDataSecret,
        );
        const encodedMlsCiphertext = tlspl.encode([mlsCiphertext.encoder]);
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [[decodedMlsCiphertext], ] = tlspl.decode(
            [MLSCiphertext.decode], encodedMlsCiphertext,
        );
        const receiverHashRatchet = new HashRatchet(
            x25519HkdfSha256Aes128Gcm, 4, new Uint8Array(secret),
        );
        const decryptedMlsPlaintext = await decodedMlsCiphertext.decrypt(
            x25519HkdfSha256Aes128Gcm,
            receiverHashRatchet,
            senderDataSecret,
        );
        expect(decryptedMlsPlaintext).toEqual(mlsPlaintext);
        expect(await decryptedMlsPlaintext.verify(sha256, signingPubKey, groupContext)).toBe(true);
    });
});
