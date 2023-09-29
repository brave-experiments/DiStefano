# DiStefano

An implementation of the 'DiStefano: Decentralized Infrastructure for Sharing Trusted Encrypted Facts and Nothing More' protocol. Find the details over [our eprint paper](https://eprint.iacr.org/2023/1063.pdf).

## DiStefano

We design DiStefano: an efficient framework for generating private commitments over TLS-encrypted web traffic for a designated, untrusted third-party. DiStefano provides many improvements over previous TLS commitment systems, including: a modular security model that is applicable
to TLS 1.3 traffic, and support for generating verifiable claims using applicable zero-knowledge systems; inherent 1-out-of-n privacy for the TLS server that the client communicates with; and various cryptographic optimisations to ensure fast online performance of the TLS session. We build an open-source implementation of DiStefano integrated into the BoringSSL cryptographic library, that is used within Chromium-based Internet browsers. We show that DiStefano is practical for committing to facts in arbitrary TLS traffic, with online times that are comparable with existing TLS 1.2 solutions. We also make improvements to certain cryptographic primitives used inside DiStefano, leading to 3x and 2x improvements in online computation time and bandwidth in specific situations.

*Warning*: This code is a research prototype. Do not use it in production.

## Build and Run

For the requirements and explanation of this code see the inside READMEs, specially, [this](https://github.com/brave-experiments/DiStefano/blob/main/src/README.md) one.

## Citation

```
@misc{cryptoeprint:2023/1063,
      author = {Sofia Celi and Alex Davidson and Hamed Haddadi and Gonçalo Pestana and Joe Rowell},
      title = {DiStefano: Decentralized Infrastructure for Sharing Trusted Encrypted Facts and Nothing More},
      howpublished = {Cryptology ePrint Archive, Paper 2023/1063},
      year = {2023},
      note = {\url{https://eprint.iacr.org/2023/1063.pdf}},
      url = {https://eprint.iacr.org/2023/1063.pdf}
}
```
