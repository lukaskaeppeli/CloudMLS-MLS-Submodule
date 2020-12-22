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

// various constants

import {stringToUint8Array} from "./util";

export const EMPTY_BYTE_ARRAY = new Uint8Array(0);

// Uint8Array versions of strings
export const APPLICATION = stringToUint8Array("application");
export const AUTHENTICATION = stringToUint8Array("authentication");
export const CANDIDATE = stringToUint8Array("candidate");
export const CONFIRM = stringToUint8Array("confirm");
export const DKP_PRK = stringToUint8Array("dkp_prk");
export const EAE_PRK = stringToUint8Array("eae_prk");
export const ENCRYPTION = stringToUint8Array("encryption");
export const EPOCH = stringToUint8Array("epoch");
export const EXP = stringToUint8Array("exp");
export const EXPORTER = stringToUint8Array("exporter");
export const EXTERNAL = stringToUint8Array("external");
export const HANDSHAKE = stringToUint8Array("handshake");
export const HPKE = stringToUint8Array("HPKE");
export const INFO_HASH = stringToUint8Array("info_hash");
export const INIT = stringToUint8Array("init");
export const KEY = stringToUint8Array("key");
export const MLS10 = stringToUint8Array("mls10 ");
export const MEMBER = stringToUint8Array("member");
export const MEMBERSHIP = stringToUint8Array("membership");
export const NODE = stringToUint8Array("node");
export const NONCE = stringToUint8Array("nonce");
export const PATH = stringToUint8Array("path");
export const PSK_HASH = stringToUint8Array("psk_hash");
export const PSK_ID_HASH = stringToUint8Array("psk_id_hash");
export const RESUMPTION = stringToUint8Array("resumption");
export const SEC = stringToUint8Array("sec");
export const SECRET = stringToUint8Array("secret");
export const SENDER_DATA = stringToUint8Array("sender data");
export const SHARED_SECRET = stringToUint8Array("shared_secret");
export const SK = stringToUint8Array("sk");
export const TREE = stringToUint8Array("tree");
export const WELCOME = stringToUint8Array("welcome");

// uint16
export enum ExtensionType {
    Capabilities = 1,
    Lifetime = 2,
    KeyId = 3,
    ParentHash = 4,
    RatchetTree = 5,
}

// uint16
export enum CredentialType {
    Basic = 1,
    X509 = 2,
}

// See RFC 8446 and the IANA TLS SignatureScheme registry
export enum SignatureScheme {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,

    /* ECDSA algorithms */
    ecdsa_secp256r1_sha256 = 0x0403,
    ecdsa_secp384r1_sha384 = 0x0503,
    ecdsa_secp521r1_sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,

    /* EdDSA algorithms */
    ed25519 = 0x0807,
    ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,

    /* Legacy algorithms */
    rsa_pkcs1_sha1 = 0x0201,
    ecdsa_sha1 = 0x0203,
}

// uint8
export enum ProtocolVersion {
    Reserved = 0,
    Mls10 = 1,
}

// uint8
export enum ContentType {
    Reserved = 0,
    Application = 1,
    Proposal = 2,
    Commit = 3,
}

// uint8
export enum SenderType {
    Reserved = 0,
    Member = 1,
    Preconfigured = 2,
    NewMember = 3,
}

// uint8
export enum ProposalType {
    Reserved =0,
    Add = 1,
    Update = 2,
    Remove = 3,
    Psk = 4,
    Reinit = 5,
    ExternalInit = 6,
}

// uint8
export enum ProposalOrRefType {
    Reserved = 0,
    Proposal = 1,
    Reference = 2,
}

// uint8
export enum NodeType {
    Reserved = 0,
    Leaf = 1,
    Parent = 2,
}
