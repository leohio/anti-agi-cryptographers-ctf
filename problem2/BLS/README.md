# Elliptic curve BLS signatures

An implementation of the [BLS digital signature scheme ](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-04) on the BLS12-381 curve from scratch. Requires python 3.9, but has no other dependencies.

The key and signature encoding conforms to the [IRTF standard](https://tools.ietf.org/html/draft-irtf-cfrg-pairing-friendly-curves-09#appendix-C), but the signature itself is not standard, since we use a simpler (and probably insecure) hashing function.

NOTE: This is just a student project. It is insecure and inefficient. Don't use it in real projects!
