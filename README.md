# nuc

A TypeScript library for working with Nillion's authentication system.

[![CI](https://github.com/NillionNetwork/nuc-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/NillionNetwork/nuc-ts/actions/workflows/ci.yaml)
[![CD](https://github.com/NillionNetwork/nuc-ts/actions/workflows/cd.yaml/badge.svg)](https://github.com/NillionNetwork/nuc-ts/actions/workflows/cd.yaml)
![GitHub package.json version](https://img.shields.io/github/package-json/v/NillionNetwork/nuc-ts)
[![npm](https://img.shields.io/npm/v/@nillion/nuc)](https://www.npmjs.com/package/@nillion/nuc)

## Installation and Usage
The library can be imported in the usual ways:

    import * as Nuc from '@nillion/nuc';

## Development
This project is managed via [pnpm](https://pnpm.io/). To install dependencies run:

    pnpm install

## Documentation
The documentation can be generated automatically from the source files using [TypeDoc](https://typedoc.org/):

    pnpm docs

## Testing and Conventions
All unit tests are executed and their coverage is measured when using [vitest](https://vitest.dev/):

    pnpm test --coverage

Style conventions are enforced using [Biome](https://biomejs.dev/):

    biome check

## Contributions
In order to contribute to the source code, open an issue or submit a pull request on the [GitHub page](https://github.com/nillionnetwork/nuc-ts) for this library.

## Versioning
The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).

## Publishing
This library can be published as a [package on npmjs](https://www.npmjs.com/package/@nillion/nuc) via the GitHub Actions workflow.

## License
This project is licensed under the [MIT License](./LICENSE).