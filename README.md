# 🍓 Strawberry: A JAM Client Implementation in Go

Welcome to Strawberry, our implementation of the JAM client for Polkadot, written in Go. This project is part of Eiger's effort to contribute to the Polkadot ecosystem by providing a robust and efficient client implementation.


## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Introduction

Strawberry is an implementation of the JAM (JOIN-ACCUMULATE MACHINE) client for Polkadot, developed in Go. This implementation aims to provide a lightweight, performant, and secure JAM client.

For more information about JAM, read the [graypaper](https://graypaper.com).

## Features

- Written in Go for performance and reliability
- Currently implementing M1 IMPORTER: State-transitioning conformance tests pass and can import blocks.
- Easy to configure and extend

## Installation

To install Strawberry, ensure you have Go installed on your system. Follow the steps below to get started:

1. Clone the repository:
    ```bash
    git clone https://github.com/eigerco/strawberry.git
    cd strawberry
    ```

2. Build the project:
    ```bash
    
    ```

3. Run the executable:
    ```bash
    
    ```

## Usage


- To start the client:
    ```bash

    ```

## Run tests

### Unit tests

```shell
make test
```

### Integration tests
Integration tests validate our code using the test vectors provided by [this](https://github.com/w3f/jamtestvectors) repository.
All integration tests are grouped within the `tests/integrations` folder, and the test cases/vectors (JSON and BIN files) are located in the `tests/integration/vectors` directory.
To execute these tests, use the following command:
```shell
make integration
```

## Contributing

We welcome contributions to Strawberry. Before contributing please read the [CONTRIBUTING](CONTRIBUTING.md) file for details.


## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgements

We would like to thank the Web3 Foundation for their support and the Polkadot community for their continuous contributions and feedback.

---

If you have any questions contact us at hello@eiger.co

