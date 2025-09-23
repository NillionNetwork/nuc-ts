/** A multicodec name, e.g., 'secp256k1-pub' */
export type Multicodec = "secp256k1-pub";

/**
 * Represents a parsed did:key object.
 *
 * Reference: https://w3c-ccg.github.io/did-key-spec/
 */
export type DidKey = {
  readonly didString: string;
  readonly method: "key";
  readonly multicodec: Multicodec;
  readonly publicKeyBytes: Uint8Array;
  readonly toJSON: () => string;
};

/**
 * Represents a parsed did:ethr object.
 *
 * Reference: https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md
 */
export type DidEthr = {
  readonly didString: string;
  readonly method: "ethr";
  readonly address: string;
  readonly toJSON: () => string;
};

/**
 * Represents a parsed `did:nil` object.
 * @deprecated This will be removed in version 0.3.0. Use `DidKey` instead.
 */
export type DidNil = {
  readonly didString: string;
  readonly method: "nil";
  readonly publicKeyBytes: Uint8Array;
  readonly toJSON: () => string;
};

/**
 * A union of all supported Did types.
 */
export type Did = DidKey | DidEthr | DidNil;
