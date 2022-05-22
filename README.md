# CloudMLS: MLS Submodule
This repository is a fork of https://gitlab.matrix.org/matrix-org/mls-ts from Hubert Chathi,
which is a proof of concept implementation ot the Message Layer Security (MLS) Protocol, documented
on https://messaginglayersecurity.rocks.

## CloudMLS
This repository is just one of four repositories that belong to the CloudMLS project.
The project includes:

-  Key Server: [https://github.com/lukaskaeppeli/CloudMLS-KeyServer](https://github.com/lukaskaeppeli/CloudMLS-KeyServer)
 
-  The library:  
  [https://github.com/lukaskaeppeli/CloudMLS](https://github.com/lukaskaeppeli/CloudMLS)  
  [https://www.npmjs.com/package/cloudmls](https://www.npmjs.com/package/cloudmls)

-  Telegram example: [https://github.com/lukaskaeppeli/CloudMLS-TelegramExample](https://github.com/lukaskaeppeli/CloudMLS-TelegramExample)

## Contribution
We extended the original version by allowing important data structures to be serialized and
fixing some minor bugs. While our extension weaken the security guarantees compared to the 
original implementation, they allow a cloud-based end-to-end encryption scheme. We list all
major changes in the following:

### Serializing Group objects

The data structure `Group` (src/group.ts) is required for all
group-specific operations like commits as well as for encrypting and
decrypting messages. We were therefore required to serialize the `Group`
objects as well as create them from serialized versions. As a data
serializable structure, we relied on JSON objects, which can be sent in
an HTTP POST request without further transformations. In order to
serialize a `Uint8Array`, the Node.js library byte-base64 is a very
efficient option offering fast transformation between `Uint8Array` and
base64 strings.

### Serializing RatchetTreeView objects

Each `Group` object contains a `RatchetTreeView` object representing the
current ratchet tree. Because this data structure is required for
encrypting and decrypting messages, its state needs to be serialized
too. Using the same techniques as for the `Group` objects, efficient
serialization and parsing are achieved.

### Use of LenientHashRatchets

In the implementation from Hubert Chathi are two types of hash ratchets
defined. The standard `HashRatchet` object represents the specification
of the MLS protocol, whereas the `LenientHashRatchtet` objects allow
deriving the same encryption keys multiple times. In a cloud-based
setting, we require re-deriving the same keys because users might want
to read the same message on multiple devices. Another option would be to
store the first ratchet of each group member and use this for further
key derivations. This approach is documented separately in Section
<a href="#subsection:base_ratchets" data-reference-type="ref"
data-reference="subsection:base_ratchets">4.1.1</a>.

### Lifetime Extension

Missing in the original implementation, we added the required `Lifetime`
extension to the `KeyPackage` object. This extension defines the period
in which a `KeyPackage` is valid. As users should update their
KeyPackages before they expire, we implemented a method determining how
long a certain `KeyPackage` is valid.

## Warning
With the words from Hubert Chathi: 
"the (current) goal of this project is *NOT* to be secure, but to
try to produce an implementation of MLS that can be used for testing ideas
around MLS.  For example, secrets may not be properly purged from memory when
they should be, and no effort was made in auditing the libraries that this
depends on.

This project might turn into a secure implementation in the future, but it
should not be relied on for security at the present time.

In addition, this implementation does not attempt to be efficient in any way,
with respect to both time and memory usage.
"

The same applies to this fork. 

## Status
As the original implementation, this fork targets draft version 11 of the MLS protocol.
At the time of writing, draft version 13 is released and could imply some changes to
the original implementation and therefore to this fork as well.
