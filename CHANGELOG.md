# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## 1.1.0 (2022-09-05)


### Features

* add a helper for pub key ([070307c](https://github.com/maidsafe/bls_ringct/commit/070307c3081c10879b3fa9bc6fb887920a6ebb7e))
* add a key_image helper ([08d5d13](https://github.com/maidsafe/bls_ringct/commit/08d5d1302b87cc6bc6ebf8fbb6e2859c48027947))
* add generic contructors ([7ce3979](https://github.com/maidsafe/bls_ringct/commit/7ce3979bfacdfd8b7ff78d3b16de79e062f88bb4))
* add input and key image uniqueness checks to tx verify ([9ed8fb1](https://github.com/maidsafe/bls_ringct/commit/9ed8fb1ef0c090731762b34c0eb53baffaa3044f))
* add serde serialization as a feature flag ([6cdcc25](https://github.com/maidsafe/bls_ringct/commit/6cdcc25c5a753b020030f402d488f8b02de372a6))
* complete ringct with bulletproofs ([1b7811a](https://github.com/maidsafe/bls_ringct/commit/1b7811a81c28c0da4f750b437f42c642dce73bbc))
* derive [de-]serialize for Error ([05eff50](https://github.com/maidsafe/bls_ringct/commit/05eff501cee0f262f504bf5c14b586f1d8eb433a))
* generate message-to-sign within RingCtMaterial::sign() ([6bfa1e5](https://github.com/maidsafe/bls_ringct/commit/6bfa1e59c1876041b66fb422cfea3f9de9a2a38b))
* implement Ord and PartialOrd for RingCtTransaction using its hash ([92e36d5](https://github.com/maidsafe/bls_ringct/commit/92e36d5a76cf3809a0ffe7ebf5711b5409c0f128))
* make a common key_image helper ([cdc961f](https://github.com/maidsafe/bls_ringct/commit/cdc961f8000323f9baffb1ca001874eea615e122))
* more generic key_image and public_key helpers ([f5c3809](https://github.com/maidsafe/bls_ringct/commit/f5c38094053284a7d8260f879bd12d9ad96ead87))
* randomize pi in each ring independently ([279b248](https://github.com/maidsafe/bls_ringct/commit/279b248e18ab21303ea1415ffec5b78c35c865ba))
* refactor MlsagMaterial to build message in RingCtTransaction::verify() ([aa51625](https://github.com/maidsafe/bls_ringct/commit/aa51625c94c6d3194a02aa7164ed8f1088f87de1))
* **ringct:** working ringct signatures at last! ([81fdaae](https://github.com/maidsafe/bls_ringct/commit/81fdaaed353005f85143b8cd367ce0c4d1436051))


### Bug Fixes

* add pi() fn to compute pi when needed. also renames key_image variable ([6697046](https://github.com/maidsafe/bls_ringct/commit/6697046fb9618e530b03cf6efb1f581c2017d035))
* call prove_single_with_rng() instead of prove_single(). ([c1a94d3](https://github.com/maidsafe/bls_ringct/commit/c1a94d3a64c2028464446160e1e4a5c0430bc86f))
* include public_key in OutputProof ([12a4f6c](https://github.com/maidsafe/bls_ringct/commit/12a4f6c9d14267cf42f10543b0696acff4c99967))
* revert to original Cargo deps ([ee43688](https://github.com/maidsafe/bls_ringct/commit/ee43688a00639cd8bccd2b15fcfef781a9fd6063))
* verify pubkey are unique across inputs ([14205a7](https://github.com/maidsafe/bls_ringct/commit/14205a7027f23d89e3d351cf53cc6ac8b50902b5))

## 0.2.1

* Implementing Ord and PartialOrd for RingCtTransaction based on its hash value

## 0.2.0

* Derive Eq and PartialEq from RingCtTransaction, MlsagSignature and OutputProof structs

## 0.1.0

* Very first release of this crate.
