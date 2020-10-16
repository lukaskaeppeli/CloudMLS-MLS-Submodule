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

import {concatUint8Array, EMPTY_BYTE_ARRAY, stringToUint8Array} from "../util";

// 4.  Cryptographic Dependencies

/** Key Encapsulation Mechanism
 */
export interface KEM {
    /** Generate a random key pair.
     */
    generateKeyPair(): Promise<[KEMPrivateKey, KEMPublicKey]>;
    /** Derive a key pair from the byte array `ikm`, where `ikm` SHOULD have at
     * least `privateKeyLength` bytes of entropy.
     */
    deriveKeyPair(ikm: Uint8Array): Promise<[KEMPrivateKey, KEMPublicKey]>;
    /** Parse the byte string "enc" of length "Npk" to recover a public key
     * (note: this function can raise an error upon "enc" deserialization
     * failure)
     */
    deserialize(enc: Uint8Array): Promise<KEMPublicKey>;

    /** The length in bytes of a KEM shared secret produced by this KEM. "Nsecret" */
    secretLength: number;
    /** The length in bytes of an encapsulated key produced by this KEM. "Nenc" */
    encodingLength: number;
    /** The length in bytes of an encoded public key for this KEM. "Npk" */
    publicKeyLength: number;
    /** The length in bytes of an encoded private key for this KEM. "Nsk" */
    privateKeyLength: number;

    /** The identifier for this KEM */
    id: number;
}

export async function defaultGenerateKeyPair(): Promise<[KEMPrivateKey, KEMPublicKey]> {
    const ikm = new Uint8Array(this.privateKeyLength);
    window.crypto.getRandomValues(ikm);
    const ret = this.deriveKeyPair(ikm);
    ikm.fill(0);
    return ret;
}

export abstract class KEMPublicKey {
    /** Produce a byte string of length `KEM.publicKeyLength` encoding the
     * public key.  The encoding can be passed to `KEM.deserialize` to recover
     * the public key.
     */
    abstract serialize(): Promise<Uint8Array>;
    /** Generate an ephemeral, fixed-length symmetric key (the KEM shared
     * secret) and a fixed-length encapsulation of that key that can be
     * decapsulated by the holder of the private key corresponding to "pk"
     */
    abstract encapsulate(): Promise<[Uint8Array, Uint8Array]>;
}

export abstract class KEMPrivateKey {
    /** Use the private key "sk" to recover the ephemeral symmetric key (the
     * KEM shared secret) from its encapsulated representation "enc"
     */
    abstract decapsulate(enc: Uint8Array): Promise<Uint8Array>;
}

// TODO: authEncap and authDecap

type extractFunc = (salt: Uint8Array | undefined, ikm: Uint8Array) => Promise<Uint8Array>;
type expandFunc = (prk: Uint8Array, info: Uint8Array | undefined, length: number) => Promise<Uint8Array>;

/** Key Derivation Function
 */
export interface KDF {
    /** Extract a pseudorandom key of fixed length "Nh" bytes from input keying
     * material "ikm" and an optional byte string "salt"
     */
    extract: extractFunc;
    /** Expand a pseudorandom key "prk" using optional string "info" into "length"
     * bytes of output keying material
     */
    expand: expandFunc;

    /** The output size of the "Extract()" function in bytes. "Nh"
     */
    extractLength: number;
    /** The output length of the underlying hash function in bytes
     */
    hashLength: number;

    /** The identifier for this KEM */
    id: number;
}

const HPKE_IDENTIFIER = stringToUint8Array("HPKE-05 ");

// def LabeledExtract(salt, label, ikm)
async function labeledExtract(
    kdf: KDF,
    suiteId: Uint8Array,
    salt: Uint8Array | undefined,
    label: Uint8Array,
    ikm: Uint8Array,
): Promise<Uint8Array> {
    const labeledIkm = concatUint8Array([HPKE_IDENTIFIER, suiteId, label, ikm]);
    return kdf.extract(labeledIkm, salt);
}

// def LabeledExpand(prk, label, info, L):
async function labeledExpand(
    kdf: KDF,
    suiteId: Uint8Array,
    prk: Uint8Array,
    label: Uint8Array,
    info: Uint8Array | undefined,
    length: number,
): Promise<Uint8Array> {
    const labeledInfo = concatUint8Array([
        Uint8Array.from([length >> 8 & 0xff, length & 0xff]),
        HPKE_IDENTIFIER,
        suiteId, label, info,
    ]);
    return kdf.expand(prk, labeledInfo, length);
}

/** Authenticated Encryption and Associated Data
 */
export interface AEAD {
    /** Encrypt and authenticate plaintext "pt" with associated data "aad"
     * using symmetric key "key" and nonce "nonce", yielding ciphertext and tag
     * "ct" (note: this function can raise a "NonceOverflowError" upon failure)
     */
    seal(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array>;
    /** Decrypt ciphertext and tag "ct" using associated data "aad" with
     * symmetric key "key" and nonce "nonce", returning plaintext message "pt"
     * (note: this function can raise an "OpenError" or "NonceOverflowError"
     * upon failure)
     */
    open(key: Uint8Array, nonce: Uint8Array, aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array>;

    /** The length in bytes of a key for this algorithm. "Nk" */
    keyLength: number;
    /** The length in bytes of a nonce for this algorithm. "Nn" */
    nonceLength: number;

    /** The identifier for this KEM */
    id: number;
}

// 4.1.  DH-Based KEM

/** Diffie-Hellman group
 */
export interface DH {
    /** Generate an ephemeral key pair "(skX, pkX)" for the DH group in use.
     */
    generateKeyPair(): Promise<[DHPrivateKey, DHPublicKey]>;
    /** Generate an ephemeral key pair "(skX, pkX)" for the DH group in use.
     */
    deriveKeyPair(ikm: Uint8Array): Promise<[DHPrivateKey, DHPublicKey]>;

    /** Parse a byte string of length "Npk" to recover a public key (note: this
     * function can raise an error upon "enc" deserialization failure)
     */
    deserialize(enc: Uint8Array): Promise<DHPublicKey>;

    /** The length in bytes of an encoded public key
     */
    publicKeyLength: number;
    /** The length in bytes of a Diffie-Hellman shared secret produced by
     * `DHPublicKey.dh`.
     */
    secretLength: number;
    /** The length in bytes of a Diffie-Hellman private key
     */
    privateKeyLength: number;
}

export abstract class DHPrivateKey {
}

export abstract class DHPublicKey {
    /** Perform a non-interactive DH exchange using the private key "sk" and
     * public key "pk" to produce a Diffie-Hellman shared secret of length "Ndh"
     */
    abstract dh(privKey: DHPrivateKey): Promise<Uint8Array>;
    /** Produce a byte string of length "Npk" encoding the public key "pk"
     */
    abstract serialize(): Promise<Uint8Array>;
}

const EAE_PRK = stringToUint8Array("eae_prk");
const SHARED_SECRET = stringToUint8Array("shared_secret");

export function makeDHKEM(dhGroup: DH, kdf: KDF, kemId: number): KEM {
    const suiteId = stringToUint8Array("KEMxx");
    suiteId[3] = kemId >> 8 & 0xff;
    suiteId[4] = kemId & 0xff;

    async function extractAndExpand(dhSecret: Uint8Array, kemContext: Uint8Array): Promise<Uint8Array> {
        const eaePrk = await labeledExtract(
            kdf, suiteId,
            EMPTY_BYTE_ARRAY, // salt
            EAE_PRK, // label
            dhSecret, // ikm
        );
        const sharedSecret = await labeledExpand(
            kdf, suiteId,
            eaePrk, // prk
            SHARED_SECRET, // label
            kemContext, // info
            kdf.hashLength,
        );
        return sharedSecret;
    }

    class PublicKey extends KEMPublicKey {
        constructor(private readonly dhPubKey: DHPublicKey) { super(); }
        serialize(): Promise<Uint8Array> { return this.dhPubKey.serialize(); }
        async encapsulate(): Promise<[Uint8Array, Uint8Array]> {
            const [privateKey, publicKey] = await dhGroup.generateKeyPair();
            const dhSecret = await this.dhPubKey.dh(privateKey);
            const enc = await publicKey.serialize();

            const pkRm = await this.dhPubKey.serialize();
            const kemContext = concatUint8Array([enc, pkRm]);

            const sharedSecret = await extractAndExpand(dhSecret, kemContext)
            return [sharedSecret, enc];
        }
    }

    class PrivateKey extends KEMPrivateKey {
        constructor(
            private readonly dhPrivKey: DHPrivateKey,
            private readonly dhPubKey: DHPublicKey,
        ) { super(); }
        async decapsulate(enc: Uint8Array): Promise<Uint8Array> {
            const pkE = await dhGroup.deserialize(enc)
            const dhSecret = await pkE.dh(this.dhPrivKey);

            const pkRm = await this.dhPubKey.serialize();
            const kemContext = concatUint8Array([enc, pkRm]);

            const sharedSecret = await extractAndExpand(dhSecret, kemContext)
            return sharedSecret;
        }
        /* FIXME:
def AuthEncap(pkR, skS):
  skE, pkE = GenerateKeyPair()
  dh = concat(DH(skE, pkR), DH(skS, pkR))
  enc = Serialize(pkE)

  pkRm = Serialize(pkR)
  pkSm = Serialize(pk(skS))
  kem_context = concat(enc, pkRm, pkSm)

  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret, enc

def AuthDecap(enc, skR, pkS):
  pkE = Deserialize(enc)
  dh = concat(DH(skR, pkE), DH(skR, pkS))

  pkRm = Serialize(pk(skR))
  pkSm = Serialize(pkS)
  kem_context = concat(enc, pkRm, pkSm)

  shared_secret = ExtractAndExpand(dh, kem_context)
  return shared_secret
         */
    }

    return {
        async generateKeyPair(): Promise<[KEMPrivateKey, KEMPublicKey]> {
            const [privateKey, publicKey] = await dhGroup.generateKeyPair();
            return [new PrivateKey(privateKey, publicKey), new PublicKey(publicKey)];
        },
        async deriveKeyPair(ikm: Uint8Array): Promise<[KEMPrivateKey, KEMPublicKey]> {
            const [privateKey, publicKey] = await dhGroup.deriveKeyPair(ikm);
            return [new PrivateKey(privateKey, publicKey), new PublicKey(publicKey)];
        },
        async deserialize(enc: Uint8Array): Promise<KEMPublicKey> {
            const publicKey = await dhGroup.deserialize(enc);
            return new PublicKey(publicKey);
        },

        secretLength: kdf.hashLength,
        encodingLength: dhGroup.publicKeyLength,
        publicKeyLength: dhGroup.publicKeyLength, // HPKE says this should be dhGroup.SecretLength?
        privateKeyLength: dhGroup.privateKeyLength,

        id: kemId,
    };
}

// 5.  Hybrid Public Key Encryption

enum Mode {
    Base = 0,
    Psk,
    Auth,
    AuthPsk,
}

const PSK_MODES = [Mode.Psk, Mode.AuthPsk];

const PSK_ID_HASH = stringToUint8Array("psk_id_hash");
const INFO_HASH = stringToUint8Array("info_hash");
const PSK_HASH = stringToUint8Array("psk_hash");
const SECRET = stringToUint8Array("secret");
const KEY = stringToUint8Array("key");
const NONCE = stringToUint8Array("nonce");
const EXP = stringToUint8Array("exp");

export class HPKE {
    private readonly suiteId: Uint8Array;
    constructor(
        private readonly kem: KEM,
        private readonly kdf: KDF,
        private readonly aead: AEAD,
    ) {
        this.suiteId = concatUint8Array([
            stringToUint8Array("HPKE"),
            Uint8Array.from([
                kem.id >> 8 & 0xff, kem.id & 0xff,
                kdf.id >> 8 & 0xff, kdf.id & 0xff,
                aead.id >> 8 & 0xff, aead.id & 0xff,
            ]),
        ]);
    }

    private verifyPSKInputs(mode: Mode, psk: Uint8Array, pskId: Uint8Array): void {
        const gotPsk = (psk.byteLength != 0);
        const gotPskId = (pskId.byteLength != 0);
        if (gotPsk != gotPskId) {
            throw new Error("Inconsistent PSK inputs");
        }

        if (gotPsk && !PSK_MODES.includes(mode)) {
            throw new Error("PSK input provided when not needed");
        }
        if (!gotPsk && PSK_MODES.includes(mode)) {
            throw new Error("Missing required PSK input");
        }
    }

    private async keySchedule(
        mode: Mode,
        sharedSecret: Uint8Array,
        info: Uint8Array,
        psk: Uint8Array,
        pskId: Uint8Array,
    ): Promise<Context> {
        this.verifyPSKInputs(mode, psk, pskId);

        const pskIdHash = await labeledExtract(
            this.kdf, this.suiteId, EMPTY_BYTE_ARRAY, PSK_ID_HASH, pskId,
        );
        const infoHash = await labeledExtract(
            this.kdf, this.suiteId, EMPTY_BYTE_ARRAY, INFO_HASH, info,
        );
        const keyScheduleContext = concatUint8Array([
            Uint8Array.from([mode]), pskIdHash, infoHash,
        ]);

        const pskHash = await labeledExtract(
            this.kdf, this.suiteId, EMPTY_BYTE_ARRAY, PSK_HASH, psk,
        );

        const secret = await labeledExtract(
            this.kdf, this.suiteId, pskHash, SECRET, sharedSecret,
        );

        const key = await labeledExpand(
            this.kdf, this.suiteId,
            secret, KEY, keyScheduleContext, this.aead.keyLength,
        );
        const nonce = await labeledExpand(
            this.kdf, this.suiteId,
            secret, NONCE, keyScheduleContext, this.aead.nonceLength,
        );
        const exporterSecret = await labeledExpand(
            this.kdf, this.suiteId,
            secret, EXP, keyScheduleContext, this.kdf.extractLength,
        );

        return new Context(this.aead, key, nonce, exporterSecret);
    }

    // 5.1.1 Encryption to a public key

    /** establish a context for encrypting
     */
    async setupBaseS(pkR: KEMPublicKey, info: Uint8Array): Promise<[Uint8Array, Context]> {
        const [sharedSecret, enc] = await pkR.encapsulate();
        const keySchedule = await this.keySchedule(
            Mode.Base, sharedSecret, info, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY,
        );
        return [enc, keySchedule];
    }

    /** establish a context for decrypting
     */
    async setupBaseR(enc: Uint8Array, skR: KEMPrivateKey, info: Uint8Array): Promise<Context> {
        const sharedSecret = await skR.decapsulate(enc);
        return await this.keySchedule(
            Mode.Base, sharedSecret, info, EMPTY_BYTE_ARRAY, EMPTY_BYTE_ARRAY,
        );
    }

    // 5.1.2 Authentication using a Pre-Shared Key

    async setupPSKS(
        pkR: KEMPublicKey, info: Uint8Array, psk: Uint8Array, pskId: Uint8Array,
    ): Promise<[Uint8Array, Context]> {
        const [sharedSecret, enc] = await pkR.encapsulate();
        const keySchedule = await this.keySchedule(
            Mode.Psk, sharedSecret, info, psk, pskId,
        );
        return [enc, keySchedule];
    }

    async setupPSKR(
        enc: Uint8Array,
        skR: KEMPrivateKey,
        info: Uint8Array,
        psk: Uint8Array,
        pskId: Uint8Array,
    ): Promise<Context> {
        const sharedSecret = await skR.decapsulate(enc);
        return await this.keySchedule(Mode.Psk, sharedSecret, info, psk, pskId);
    }
}

// 5.2.  Encryption and Decryption
class Context {
    private sequence: Uint8Array;
    constructor(
        readonly aead: AEAD,
        private readonly key: Uint8Array,
        private readonly nonce: Uint8Array,
        private readonly exporterSecret: Uint8Array,
    ) {
        this.sequence = new Uint8Array(aead.nonceLength);
    }

    computeNonce(): Uint8Array {
        return this.nonce.map((el, idx) => el ^ this.sequence[idx]);
    }

    incrementSeq(): void {
        let i: number;
        for (i = this.aead.nonceLength - 1; i >= 0; i--) {
            const v = this.sequence[i];
            if (v == 0xff) {
                this.sequence[i] = 0;
            } else {
                this.sequence[i] = v + 1;
                break;
            }
        }
        if (i < 0) {
            throw new Error("Nonce overflow");
        }
    }

    async seal(aad: Uint8Array, pt: Uint8Array): Promise<Uint8Array> {
        const ct = await this.aead.seal(this.key, this.computeNonce(), aad, pt);
        this.incrementSeq();
        return ct;
    }

    async open(aad: Uint8Array, ct: Uint8Array): Promise<Uint8Array> {
        const pt = await this.aead.open(this.key, this.computeNonce(), aad, ct);
        this.incrementSeq();
        return pt;
    }
}
