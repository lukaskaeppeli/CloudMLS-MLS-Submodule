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

// methods for creating signatures

import {EMPTY_BYTE_ARRAY} from "./constants";
import {eddsa as EdDSA} from "elliptic";

const subtle = window.crypto.subtle;

export interface SignatureScheme {
    generateKeyPair(): Promise<[SigningPrivateKey, SigningPublicKey]>;
    deriveKeyPair(ikm: Uint8Array): Promise<[SigningPrivateKey, SigningPublicKey]>;

    deserializePrivate(enc: Uint8Array): Promise<SigningPrivateKey>;
    deserializePublic(enc: Uint8Array): Promise<SigningPublicKey>;

    privateKeyLength: number;
    publicKeyLength: number;
}

export interface SigningPrivateKey {
    sign(message: Uint8Array): Promise<Uint8Array>;
    serialize(): Promise<Uint8Array>;
}

export interface SigningPublicKey {
    verify(message: Uint8Array, signature: Uint8Array): Promise<boolean>;
    serialize(): Promise<Uint8Array>;
}

const ed25519 = new EdDSA('ed25519');

export const Ed25519: SignatureScheme = {
    async generateKeyPair(): Promise<[SigningPrivateKey, SigningPublicKey]> {
        const ikm = new Uint8Array(Ed25519.privateKeyLength);
        window.crypto.getRandomValues(ikm);
        const keyPair = ed25519.keyFromSecret(ikm);
        return [new Ed25519PrivateKey(keyPair), new Ed25519PublicKey(keyPair)];
    },

    async deriveKeyPair(ikm: Uint8Array): Promise<[SigningPrivateKey, SigningPublicKey]> {
        const ikmKey = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
        const derivedKey = await subtle.deriveBits(
            {name: "HKDF", hash: "SHA-256", salt: EMPTY_BYTE_ARRAY},
            ikmKey, Ed25519.privateKeyLength * 8,
        );
        const derivedKeyArr = new Uint8Array(derivedKey);
        const keyPair = ed25519.keyFromSecret(derivedKeyArr);
        derivedKeyArr.fill(0);
        return [new Ed25519PrivateKey(keyPair), new Ed25519PublicKey(keyPair)];
    },

    async deserializePrivate(enc: Uint8Array): Promise<SigningPrivateKey> {
        const keyPair = ed25519.keyFromSecret(enc);
        return new Ed25519PrivateKey(keyPair);
    },
    async deserializePublic(enc: Uint8Array): Promise<SigningPublicKey> {
        const keyPair = ed25519.keyFromPublic(enc)
        return new Ed25519PublicKey(keyPair);
    },

    privateKeyLength: 32,
    publicKeyLength: 32,
}

class Ed25519PrivateKey implements SigningPrivateKey {
    constructor(private readonly keyPair) {}

    async sign(message: Uint8Array): Promise<Uint8Array> {
        return Uint8Array.from(this.keyPair.sign(message).toBytes());
    }
    async serialize(): Promise<Uint8Array> {
        return Uint8Array.from(this.keyPair.getSecret());
    }
}

class Ed25519PublicKey implements SigningPublicKey {
    constructor(private readonly keyPair) {}

    async verify(message: Uint8Array, signature: Uint8Array): Promise<boolean> {
        return this.keyPair.verify(message, [...signature.values()]);
    }
    async serialize(): Promise<Uint8Array> {
        return Uint8Array.from(this.keyPair.getPublic());
    }
}
