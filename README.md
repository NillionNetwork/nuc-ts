# @nillion/nuc

A TypeScript library for working with Nillion's authentication system.

[![CI](https://github.com/NillionNetwork/nuc-ts/actions/workflows/ci.yaml/badge.svg)](https://github.com/NillionNetwork/nuc-ts/actions/workflows/ci.yaml)
[![CD](https://github.com/NillionNetwork/nuc-ts/actions/workflows/cd.yaml/badge.svg)](https://github.com/NillionNetwork/nuc-ts/actions/workflows/cd.yaml)
![GitHub package.json version](https://img.shields.io/github/package-json/v/NillionNetwork/nuc-ts)
[![npm](https://img.shields.io/npm/v/@nillion/nuc)](https://www.npmjs.com/package/@nillion/nuc)

## Installation and Usage

The library can be imported in the usual ways:

    import * as Nuc from '@nillion/nuc';

### Complete Usage Example

This example demonstrates the primary workflow of creating delegation and invocation tokens:

```typescript
import {Keypair, Builder, decodeBase64Url, serializeBase64Url, validate} from '@nillion/nuc';

// Step 1: Create keypairs
const rootKeypair = Keypair.generate();
const userKeypair = Keypair.generate();
const serviceKeypair = Keypair.generate();

// Step 2: Create the service DID that will receive the invocation
const serviceDid = serviceKeypair.toDid();
const serviceDidString = serviceDid.didString; // e.g., "did:key:zDnae..."

// Step 3: Build a root delegation token
// This grants capabilities to the user's keypair
const rootDelegation = Builder.delegation()
  .audience(userKeypair.toDid())        // Who can use this delegation
  .subject(userKeypair.toDid())         // Who the delegation is about
  .command("/nil/db/collections/read")  // The authorised command namespace
  .policy([                             // Policy rules that must be satisfied
    ["==", ".command", "/db/read"],
    ["!=", ".args.table", "secrets"]
  ])
  .expiresAt(Date.now() + 3600 * 1000)  // Expires in 1 hour
  .build(rootKeypair);

// Step 4: Build an invocation token from the delegation
// This actually invokes the granted capability
const invocation = Builder.invoking(rootDelegation)
  .audience(serviceDid)                 // The service that will process this
  .arguments({collection: "users"})   // Arguments for the command
  .build(userKeypair);

// Step 5: Serialise for transmission
const tokenString = serializeBase64Url(invocation);
console.log("Token to send:", tokenString);

// Step 6: (Optional) Decode and validate the token
// This would typically happen on the receiving service
const decoded = decodeBase64Url(tokenString);

try {
  validate(decoded, {
    rootIssuers: [rootKeypair.toDid()],
    params: {
      tokenRequirements: {
        type: "invocation",
        audience: serviceDidString  // Use the DID string for validation
      }
    },
    context: {
      // Additional context for policy evaluation
      environment: "production"
    }
  });
  console.log("Token is valid!");
} catch (error) {
  console.error("Validation failed:", error.message);
}
```

This example demonstrates:

- Creating keypairs for different actors in the system
- Using actual DIDs generated from keypairs (not hardcoded strings)
- Building a delegation token that grants specific capabilities
- Creating an invocation token that exercises those capabilities
- Serializing tokens for network transmission
- Decoding and validating tokens with comprehensive checks using the DID string

## Development

This project is managed via [pnpm](https://pnpm.io/). To install dependencies run: `pnpm install`

### Debugging and Logging

The library uses [pino](https://github.com/pinojs/pino) for structured logging. You can control the log level to help debug issues:

1. **Node.js**: Set the `NILLION_LOG_LEVEL` environment variable
   ```bash
   NILLION_LOG_LEVEL=debug pnpm test
   NILLION_LOG_LEVEL=trace node your-script.js
   ```

2. **Browser**: Use the developer console to configure logging
   ```javascript
   // Set log level via localStorage
   localStorage.setItem("NILLION_LOG_LEVEL", "debug");
   
   // Or use the global API (if available)
   window.__NILLION.setLogLevel("debug");
   ```

3. **Available log levels** (from most to least verbose):
    - `trace` - Extremely detailed debugging information
    - `debug` - Detailed debugging information
    - `info` - General informational messages
    - `warn` - Warning messages
    - `error` - Error messages only
    - `silent` - Disable all logging

## Documentation

The documentation can be generated automatically from the source files using [TypeDoc](https://typedoc.org/):
`pnpm docs`

## Testing and Conventions

All unit tests are executed and their coverage is measured when using [vitest](https://vitest.dev/):
`pnpm test --coverage`

Style conventions are enforced using [Biome](https://biomejs.dev/): `biome check`

## Contributions

In order to contribute to the source code, open an issue or submit a pull request on the [GitHub page](https://github.com/nillionnetwork/nuc-ts) for this library.

## Versioning

The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).

## Publishing

This library can be published as a [package on npmjs](https://www.npmjs.com/package/@nillion/nuc) via the GitHub Actions workflow.

## License

This project is licensed under the [MIT License](./LICENSE).
