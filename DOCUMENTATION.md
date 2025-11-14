# Usage Documentation

## Installation

The library can be imported in the usual ways:

```bash
pnpm install @nillion/nuc
```

```typescript
import { Builder, Codec, Signer, Validator } from '@nillion/nuc';
```

## Core Concepts

A Nuc (Nillion User Controlled) token is a type of capability-based authorisation token inspired by the UCAN specification. It grants specific permissions from a sender to a receiver. Three core claims define the actors in this relationship:

| Claim     | Role                    | Description                                                                                                                                                   |
|:----------|:------------------------|:--------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **`iss`** | **Issuer (Sender)**     | The principal who created and signed the token.                                                                                                               |
| **`aud`** | **Audience (Receiver)** | The principal the token is addressed to. This is the only entity that can use (i.e., invoke or delegate) the token.                                           |
| **`sub`** | **Subject**             | The principal the token is "about". It represents the identity whose authority is being granted. This value must stay the same throughout a delegation chain. |

In a simple, two-party delegation, the `aud` and `sub` are often the same. When the Audience creates a new, chained token, it becomes the `iss` of the new token.

## Complete Usage Example

This example demonstrates the primary workflow of creating delegation and invocation tokens:

```typescript
import { Signer, Builder, Codec, Validator } from '@nillion/nuc';

// Step 1: Create Signers for different parties
// A root authority (e.g., for a server-side process with a private key)
const rootSigner = Signer.fromPrivateKey("YOUR_ROOT_PRIVATE_KEY_HEX");

// A user identity, newly generated for this session
const userSigner = Signer.generate();

// A service that will receive the final invocation
const serviceSigner = Signer.generate();

// Step 2: Get the Dids for the user and service
const userDid = await userSigner.getDid();
const serviceDid = await serviceSigner.getDid();
const serviceDidString = serviceDid.didString; // e.g., "did:key:zDnae..."

// Step 3: Build a root delegation token
// This grants capabilities from the root to the user
const rootDelegation = await Builder.delegation()
  .audience(userDid)                      // Who can use this delegation
  .subject(userDid)                       // Who the delegation is about
  .command("/nil/db/collections/read")    // The authorized command namespace
  .policy([                               // Policy rules that must be satisfied
    ["==", ".command", "/nil/db/collections"], // Command must be an attenuation
    ["!=", ".args.collection", "secrets"]
  ])
  .expiresIn(3600 * 1000)                 // Expires in 1 hour
  .sign(rootSigner);

// Step 4: Build an invocation token from the delegation
// The user invokes their granted capability for the service
const invocation = await Builder.invocationFrom(rootDelegation)
  .audience(serviceDid)                   // The service that will process this
  .command("/nil/db/collections/read")    // The specific command being invoked
  .arguments({ collection: "users" })       // Arguments for the command
  .sign(userSigner); // Signed by the user

// Step 5: Serialize for transmission
const tokenString = Codec.serializeBase64Url(invocation);
console.log("Token to send:", tokenString);

// Step 6: (Optional) Parse and validate the token
// This would typically happen on the receiving service.
const rootDid = await rootSigner.getDid();

try {
  const decoded = Validator.parse(tokenString, {
    rootIssuers: [rootDid.didString], // Use the Did string for validation
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
  console.log("Token is valid!", decoded);
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
