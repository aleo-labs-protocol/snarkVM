<p align="center">
    <img alt="snarkVM" width="1412" src=".resources/snarkVM-banner.png">
</p>

<p align="center">
    <a href="https://github.com/aleo-labs-protocol/snarkVM/actions/workflows/ci.yml?query=branch%3Astaging"><img src="https://github.com/aleo-labs-protocol/snarkVM/actions/workflows/ci.yml/badge.svg?branch=staging"></a>
    <a href="https://codecov.io/gh/ProvableHQ/snarkVM"><img src="https://codecov.io/gh/ProvableHQ/snarkVM/branch/master/graph/badge.svg?token=cck8tS9HpO"/></a>
    <a href="https://discord.gg/aleo"><img src="https://img.shields.io/discord/700454073459015690?logo=discord"/></a>
    <a href="https://twitter.com/AleoHQ"><img src="https://img.shields.io/twitter/follow/AleoHQ?style=social"/></a>
    <a href="https://github.com/ProvableHQ/snarkVM"><img src="https://img.shields.io/badge/contributors-41-ee8449"/></a>
</p>

## Table of Contents

* [1. Overview](#1-overview)
* [2. Build Guide](#2-build-guide)
* [3. Contributors](#3-contributors)
* [4. License](#4-license)

## 1. Overview

| Package             | crates.io                                                                                                         | docs.rs                                                                                              |       `std`        |       `wasm`       | Description                                   |
|:-------------------:|:-----------------------------------------------------------------------------------------------------------------:|:----------------------------------------------------------------------------------------------------:|:------------------:|:------------------:|:----------------------------------------------|
| snarkvm             | [![crates.io](https://img.shields.io/crates/v/snarkvm)            ](https://crates.io/crates/snarkvm)             | [![docs.rs](https://img.shields.io/docsrs/snarkvm)            ](https://docs.rs/snarkvm)             | :white_check_mark: | :white_check_mark: | Meta-package that contains all other crates   |
| snarkvm-algorithms  | [![crates.io](https://img.shields.io/crates/v/snarkvm-algorithms) ](https://crates.io/crates/snarkvm-algorithms)  | [![docs.rs](https://img.shields.io/docsrs/snarkvm-algorithms) ](https://docs.rs/snarkvm-algorithms)  | :white_check_mark: | :white_check_mark: |                                               |
| snarkvm-circuit     | [![crates.io](https://img.shields.io/crates/v/snarkvm-circuit)    ](https://crates.io/crates/snarkvm-circuit)     | [![docs.rs](https://img.shields.io/docsrs/snarkvm-circuit)    ](https://docs.rs/snarkvm-circuit)     | :white_check_mark: | :white_check_mark: | Arithmetic circuits for snarkVM               |
| snarkvm-console     | [![crates.io](https://img.shields.io/crates/v/snarkvm-console)    ](https://crates.io/crates/snarkvm-console)     | [![docs.rs](https://img.shields.io/docsrs/snarkvm-console)    ](https://docs.rs/snarkvm-console)     | :white_check_mark: | :white_check_mark: |                                               |
| snarkvm-curves      | [![crates.io](https://img.shields.io/crates/v/snarkvm-curves)     ](https://crates.io/crates/snarkvm-curves)      | [![docs.rs](https://img.shields.io/docsrs/snarkvm-curves)     ](https://docs.rs/snarkvm-curves)      | :white_check_mark: | :white_check_mark: | Cryptographic curves for snarkVM              |
| snarkvm-fields      | [![crates.io](https://img.shields.io/crates/v/snarkvm-fields)     ](https://crates.io/crates/snarkvm-fields)      | [![docs.rs](https://img.shields.io/docsrs/snarkvm-fields)     ](https://docs.rs/snarkvm-fields)      | :white_check_mark: | :white_check_mark: | Arithmetic fields for snarkVM                 |
| snarkvm-ledger      | [![crates.io](https://img.shields.io/crates/v/snarkvm-ledger)     ](https://crates.io/crates/snarkvm-ledger)      | [![docs.rs](https://img.shields.io/docsrs/snarkvm-ledger)     ](https://docs.rs/snarkvm-ledger)      | :white_check_mark: | :white_check_mark: | Ledger implementation for the Aleo blockchain |
| snarkvm-parameters  | [![crates.io](https://img.shields.io/crates/v/snarkvm-parameters) ](https://crates.io/crates/snarkvm-parameters)  | [![docs.rs](https://img.shields.io/docsrs/snarkvm-parameters) ](https://docs.rs/snarkvm-parameters)  | :white_check_mark: | :white_check_mark: |                                               |
| snarkvm-synthesizer | [![crates.io](https://img.shields.io/crates/v/snarkvm-synthesizer)](https://crates.io/crates/snarkvm-synthesizer) | [![docs.rs](https://img.shields.io/docsrs/snarkvm-synthesizer)](https://docs.rs/snarkvm-synthesizer) | :white_check_mark: | :white_check_mark: | Program synthesizer for snarkVM               |
| snarkvm-utilities   | [![crates.io](https://img.shields.io/crates/v/snarkvm-utilities)  ](https://crates.io/crates/snarkvm-utilities)   | [![docs.rs](https://img.shields.io/docsrs/snarkvm-utilities)  ](https://docs.rs/snarkvm-utilities)   | :white_check_mark: | :white_check_mark: | Helper functions for snarkVM                   |
| snarkvm-wasm        | [![crates.io](https://img.shields.io/crates/v/snarkvm-wasm)       ](https://crates.io/crates/snarkvm-wasm)        | [![docs.rs](https://img.shields.io/docsrs/snarkvm-wasm)       ](https://docs.rs/snarkvm-wasm)        | :white_check_mark: | :white_check_mark: | WASM bindings for snarkVM                     |
  
For more information, visit [Welcome to Aleo](https://github.com/AleoNet/welcome) to get started.

## 2. Build Guide

### 2.1 Install Rust

We recommend installing Rust using [rustup](https://www.rustup.rs/). You can install `rustup` as follows:

- macOS or Linux:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

  For macOS users, you will need to subsequently install the following packages:
  ```bash
  brew install pkgconf
  brew install openssl
  ```

- Windows (64-bit):

  Download the [Windows 64-bit executable](https://win.rustup.rs/x86_64) or
  [Windows 32-bit executable](https://win.rustup.rs/i686) and follow the on-screen instructions.

### 2.2 Using snarkVM as a Library

snarkVM is primarily designed to be used as a library in Rust projects. Add it to your `Cargo.toml` with your favourite published version:

```toml
[dependencies]
snarkvm = "<major>.<minor>.<patch>"
```

### 2.3 Build from Source Code

You can also build snarkVM from source:

```bash
# Fetch the repository's development (staging) branch
git clone --branch staging --single-branch https://github.com/ProvableHQ/snarkVM.git 
cd snarkVM
# Build the library
cargo build --release
```

## 3. Contributors

Thank you for helping make snarkVM better!  
[🧐 What do the emojis mean?](https://allcontributors.org/docs/en/emoji-key)

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/howardwu"><img src="https://avatars.githubusercontent.com/u/9260812?v=4?s=100" width="100px;" alt="Howard Wu"/><br /><sub><b>Howard Wu</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkVM/commits?author=howardwu" title="Code">💻</a> <a href="#maintenance-howardwu" title="Maintenance">🚧</a> <a href="#ideas-howardwu" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Ahowardwu" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/raychu86"><img src="https://avatars.githubusercontent.com/u/14917648?v=4?s=100" width="100px;" alt="Raymond Chu"/><br /><sub><b>Raymond Chu</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=raychu86" title="Code">💻</a> <a href="#maintenance-raychu86" title="Maintenance">🚧</a> <a href="#ideas-raychu86" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Araychu86" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/d0cd"><img src="https://avatars.githubusercontent.com/u/23022326?v=4?s=100" width="100px;" alt="d0cd"/><br /><sub><b>d0cd</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=d0cd" title="Code">💻</a> <a href="#maintenance-d0cd" title="Maintenance">🚧</a> <a href="#ideas-d0cd" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Ad0cd" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Pratyush"><img src="https://avatars.githubusercontent.com/u/3220730?v=4?s=100" width="100px;" alt="Pratyush Mishra"/><br /><sub><b>Pratyush Mishra</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=Pratyush" title="Code">💻</a> <a href="#maintenance-Pratyush" title="Maintenance">🚧</a> <a href="#ideas-Pratyush" title="Ideas, Planning, & Feedback">🤔</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3APratyush" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://victorsintnicolaas.com/"><img src="https://avatars.githubusercontent.com/u/24724627?v=4?s=100" width="100px;" alt="vicsn"/><br /><sub><b>vicsn</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=vicsn" title="Code">💻</a> <a href="#maintenance-vicsn" title="Maintenance">🚧</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=vicsn" title="Documentation">📖</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Avicsn" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ljedrz"><img src="https://avatars.githubusercontent.com/u/3750347?v=4?s=100" width="100px;" alt="ljedrz"/><br /><sub><b>ljedrz</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=ljedrz" title="Code">💻</a> <a href="#tool-ljedrz" title="Tools">🔧</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Aljedrz" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/iamalwaysuncomfortable"><img src="https://avatars.githubusercontent.com/u/26438809?v=4?s=100" width="100px;" alt="Mike Turner"/><br /><sub><b>Mike Turner</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=iamalwaysuncomfortable" title="Code">💻</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=iamalwaysuncomfortable" title="Documentation">📖</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Aiamalwaysuncomfortable" title="Reviewed Pull Requests">👀</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/collinc97"><img src="https://avatars.githubusercontent.com/u/16715212?v=4?s=100" width="100px;" alt="Collin Chin"/><br /><sub><b>Collin Chin</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=collinc97" title="Code">💻</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=collinc97" title="Documentation">📖</a> <a href="https://github.com/ProvableHQ/snarkvm/pulls?q=is%3Apr+reviewed-by%3Acollinc97" title="Reviewed Pull Requests">👀</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://alessandrocoglio.info"><img src="https://avatars.githubusercontent.com/u/2409151?v=4?s=100" width="100px;" alt="Alessandro Coglio"/><br /><sub><b>Alessandro Coglio</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=acoglio" title="Code">💻</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=acoglio" title="Documentation">📖</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=acoglio" title="Tests">⚠️</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/niklaslong"><img src="https://avatars.githubusercontent.com/u/13221615?v=4?s=100" width="100px;" alt="Niklas Long"/><br /><sub><b>Niklas Long</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=niklaslong" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jules"><img src="https://avatars.githubusercontent.com/u/30194392?v=4?s=100" width="100px;" alt="jules"/><br /><sub><b>jules</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=jules" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/amousa11"><img src="https://avatars.githubusercontent.com/u/12452142?v=4?s=100" width="100px;" alt="Ali Mousa"/><br /><sub><b>Ali Mousa</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=amousa11" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.chenweikeng.com/"><img src="https://avatars.githubusercontent.com/u/14937807?v=4?s=100" width="100px;" alt="Weikeng Chen"/><br /><sub><b>Weikeng Chen</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=weikengchen" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/evan-schott"><img src="https://avatars.githubusercontent.com/u/53463459?v=4?s=100" width="100px;" alt="Evan Schott"/><br /><sub><b>Evan Schott</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=evan-schott" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Protryon"><img src="https://avatars.githubusercontent.com/u/8600837?v=4?s=100" width="100px;" alt="Max Bruce"/><br /><sub><b>Max Bruce</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=Protryon" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/zhiqiangxu"><img src="https://avatars.githubusercontent.com/u/1265027?v=4?s=100" width="100px;" alt="zhiqiangxu"/><br /><sub><b>zhiqiangxu</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=zhiqiangxu" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/jrchatruc"><img src="https://avatars.githubusercontent.com/u/49622509?v=4?s=100" width="100px;" alt="Javier Rodríguez Chatruc"/><br /><sub><b>Javier Rodríguez Chatruc</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=jrchatruc" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/emmorais"><img src="https://avatars.githubusercontent.com/u/13047772?v=4?s=100" width="100px;" alt="Eduardo Morais"/><br /><sub><b>Eduardo Morais</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=emmorais" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/zvolin"><img src="https://avatars.githubusercontent.com/u/34972409?v=4?s=100" width="100px;" alt="Maciej Zwoliński"/><br /><sub><b>Maciej Zwoliński</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=zvolin" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ilitteri"><img src="https://avatars.githubusercontent.com/u/67517699?v=4?s=100" width="100px;" alt="Ivan Litteri"/><br /><sub><b>Ivan Litteri</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=ilitteri" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/FranFiuba"><img src="https://avatars.githubusercontent.com/u/5733366?v=4?s=100" width="100px;" alt="Francisco Strambini"/><br /><sub><b>Francisco Strambini</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=FranFiuba" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/HarukaMa"><img src="https://avatars.githubusercontent.com/u/861659?v=4?s=100" width="100px;" alt="Haruka"/><br /><sub><b>Haruka</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/issues?q=author%3AHarukaMa" title="Bug reports">🐛</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=HarukaMa" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/StarLI-Trapdoor"><img src="https://avatars.githubusercontent.com/u/55707687?v=4?s=100" width="100px;" alt="StarLI-Trapdoor"/><br /><sub><b>StarLI-Trapdoor</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=StarLI-Trapdoor" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/vvp"><img src="https://avatars.githubusercontent.com/u/700877?v=4?s=100" width="100px;" alt="Vesa-Ville"/><br /><sub><b>Vesa-Ville</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=vvp" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/joske"><img src="https://avatars.githubusercontent.com/u/532423?v=4?s=100" width="100px;" alt="Jos Dehaes"/><br /><sub><b>Jos Dehaes</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=joske" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/apruden2008"><img src="https://avatars.githubusercontent.com/u/39969542?v=4?s=100" width="100px;" alt="apruden2008"/><br /><sub><b>apruden2008</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=apruden2008" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/evanmarshall"><img src="https://avatars.githubusercontent.com/u/1102811?v=4?s=100" width="100px;" alt="Evan Marshall"/><br /><sub><b>Evan Marshall</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/issues?q=author%3Aevanmarshall" title="Bug reports">🐛</a> <a href="https://github.com/ProvableHQ/snarkvm/commits?author=evanmarshall" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/psivesely"><img src="https://avatars.githubusercontent.com/u/3538418?v=4?s=100" width="100px;" alt="Psi Vesely"/><br /><sub><b>Psi Vesely</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=psivesely" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/swift-mx"><img src="https://avatars.githubusercontent.com/u/80231732?v=4?s=100" width="100px;" alt="swift-mx"/><br /><sub><b>swift-mx</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=swift-mx" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://www.linkedin.com/in/ignacio-avecilla-39386a191/"><img src="https://avatars.githubusercontent.com/u/63374472?v=4?s=100" width="100px;" alt="Nacho Avecilla"/><br /><sub><b>Nacho Avecilla</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=IAvecilla" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/qy3u"><img src="https://avatars.githubusercontent.com/u/65523321?v=4?s=100" width="100px;" alt="qy3u"/><br /><sub><b>qy3u</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=qy3u" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/happysalada"><img src="https://avatars.githubusercontent.com/u/5317234?v=4?s=100" width="100px;" alt="Yt"/><br /><sub><b>Yt</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=happysalada" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/unordered-set"><img src="https://avatars.githubusercontent.com/u/78592281?v=4?s=100" width="100px;" alt="Kostyan"/><br /><sub><b>Kostyan</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=unordered-set" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/stanlagermin"><img src="https://avatars.githubusercontent.com/u/40028493?v=4?s=100" width="100px;" alt="stanlagermin"/><br /><sub><b>stanlagermin</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=stanlagermin" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/sukey2008"><img src="https://avatars.githubusercontent.com/u/35202440?v=4?s=100" width="100px;" alt="Sukey"/><br /><sub><b>Sukey</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=sukey2008" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/AlexZhao6666"><img src="https://avatars.githubusercontent.com/u/136443781?v=4?s=100" width="100px;" alt="Alex Zhao"/><br /><sub><b>Alex Zhao</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=AlexZhao6666" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/ghostant-1017"><img src="https://avatars.githubusercontent.com/u/53888545?v=4?s=100" width="100px;" alt="ghost ant"/><br /><sub><b>ghost ant</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=ghostant-1017" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/psivesely"><img src="https://avatars.githubusercontent.com/u/3538418?v=4?s=100" width="100px;" alt="Psi Vesely"/><br /><sub><b>Psi Vesely</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=psivesely" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/features/security"><img src="https://avatars.githubusercontent.com/u/27347476?v=4?s=100" width="100px;" alt="Dependabot"/><br /><sub><b>Dependabot</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=dependabot" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/apps/dependabot-preview"><img src="https://avatars.githubusercontent.com/u/27347476?v=4?s=100" width="100px;" alt="Dependabot Preview"/><br /><sub><b>Dependabot Preview</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=dependabot-preview" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://allcontributors.org/"><img src="https://avatars.githubusercontent.com/u/46410174?v=4?s=100" width="100px;" alt="All Contributors"/><br /><sub><b>All Contributors</b></sub></a><br /><a href="https://github.com/ProvableHQ/snarkvm/commits?author=all-contributors" title="Documentation">📖</a></td>
    </tr>
  </tbody>
  <tfoot>
    <tr>
      <td align="center" size="13px" colspan="7">
        <img src="https://raw.githubusercontent.com/all-contributors/all-contributors-cli/1b8533af435da9854653492b1327a23a4dbd0a10/assets/logo-small.svg">
          <a href="https://all-contributors.js.org/docs/en/bot/usage">Add your contributions</a>
        </img>
      </td>
    </tr>
  </tfoot>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## 4. License

[![License: GPL v3](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE.md)
