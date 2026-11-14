Aleo uses a tailored set of pairing-friendly elliptic curves to perform efficient proof generation and verification.

|                     |  Edwards BLS12  |     BLS12-377      |
|:------------------- |:---------------:|:------------------:|
| Curve Type          | Twisted Edwards | Barreto-Lynn-Scott |
| Scalar Field Size   |    251 bits     |      253 bits      |
| Base Field Size     |    253 bits     |      377 bits      |
| G1 Compressed Size* |    32 bytes     |      48 bytes      |
| G2 Compressed Size* |       N/A       |      96 bytes      |

\* rounded to multiples of 8 bytes.

