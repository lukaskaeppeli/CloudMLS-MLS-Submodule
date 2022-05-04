# CloudMLS: MLS Submodule
This repository is a fork of https://gitlab.matrix.org/matrix-org/mls-ts from Hubert Chathi,
which is a proof of concept implementation ot the Message Layer Security (MLS) Protocol, documented
on https://messaginglayersecurity.rocks.

## Contribution
We extended the original version by allowing important data structures to be serialized and
fixing some minor bugs. While our extension weaken the security guarantees compared to the 
original implementation, they allow a cloud-based end-to-end encryption scheme.

## CloudMLS
This repository is just one of four repositories that belong to the CloudMLS project. As soon
as the other repositories are published, the links will be included here.

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
