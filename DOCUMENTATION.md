# Usage Documentation

## Installation

The library can be imported in the usual ways:

```bash
pnpm install @nillion/nuc
```

```typescript
import { Builder, Codec, Keypair, Validator } from '@nillion/nuc';
```

## Complete Usage Example

This example demonstrates the primary workflow of creating delegation and invocation tokens:

```typescript
import { Keypair, Builder, Codec, Validator } from '@nillion/nuc';

// Step 1: Create keypairs
const rootKeypair = Keypair.generate();
const userKeypair = Keypair.generate();
const serviceKeypair = Keypair.generate();

// Step 2: Create the service Did that will receive the invocation
const serviceDid = serviceKeypair.toDid();
const serviceDidString = serviceDid.didString; // e.g., "did:key:zDnae..."

// Step 3: Build a root delegation token
// This grants capabilities to the user's keypair
const rootDelegation = await Builder.delegation()
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
const invocation = await Builder.invoking(rootDelegation)
  .audience(serviceDid)                 // The service that will process this
  .arguments({collection: "users"})     // Arguments for the command
  .build(userKeypair);

// Step 5: Serialise for transmission
const tokenString = Codec.serializeBase64Url(invocation);
console.log("Token to send:", tokenString);

// Step 6: (Optional) Decode and validate the token
// This would typically happen on the receiving service
const decoded = Codec.decodeBase64Url(tokenString);

try {
  Validator.validate(decoded, {
    rootIssuers: [rootKeypair.toDid().didString], // Use the Did string for validation
    params: {
      tokenRequirements: {
        type: "invocation",
        audience: serviceDidString
      }
    },
    context: {
      // Additional context for policy evaluation
      environment: "production"
    }
  });
  console.log("Token is valid!");
} catch (error) {
  // It's safer to check the error message against exported constants
  // to avoid breaking changes if the message text is updated.
  if (error instanceof Error && error.message === Validator.TOKEN_EXPIRED) {
    console.error("Validation failed because the token is expired.");
  } else {
    console.error("An unexpected validation error occurred:", error);
  }
}
```
