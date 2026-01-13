import { ONE_HOUR_MS } from "#/constants";
import { Signer } from "#/core/signer";
import { Builder } from "#/nuc/builder";
import type { EIP1193Provider } from "viem";
import { describe, expect, it, vi } from "vitest";

const MOCK_ADDRESS = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
const MOCK_SIGNATURE =
  "0x0b8a393e876b533f443b715617c462707763c3d39589b25a3a7c64c1265ca62744e877c8e9d3d3d6b055375743b177a4199c402127270b24050d2f82c4f1c11d1b";

describe("Signer.fromEip1193Provider", () => {
  it("should create a signer, get a DID, and sign a payload", async () => {
    // 1. Mock the EIP-1193 provider (eg window.ethereum)
    const mockProvider: EIP1193Provider = {
      on: vi.fn(),
      removeListener: vi.fn(),
      request: vi.fn(async (args) => {
        if (args.method === "eth_requestAccounts") {
          return [MOCK_ADDRESS];
        }
        if (args.method === "personal_sign") {
          return MOCK_SIGNATURE;
        }
        if (args.method === "eth_signTypedData_v4") {
          return MOCK_SIGNATURE;
        }
        return null;
      }) as any,
    };

    // 2. Create the signer using the new static method
    const nucSigner = await Signer.fromEip1193Provider(mockProvider);

    // 3. Assert the DID is correctly derived
    const did = await nucSigner.getDid();
    expect(did.method).toBe("ethr");
    expect(did.didString).toBe(`did:ethr:${MOCK_ADDRESS}`);

    // 4. Assert that signing works by creating and signing an envelope
    const audience = await Signer.generate().getDid();
    const envelope = await Builder.delegation()
      .audience(audience)
      .subject(did)
      .command("/test")
      .expiresIn(ONE_HOUR_MS)
      .sign(nucSigner);

    // Assert that the signer produced a signature
    expect(envelope.nuc.signature).toBeDefined();
    // The mock returns a signature of a different length, but we just care that it's populated
    expect(envelope.nuc.signature.length).toBeGreaterThan(0);
  });

  it("should throw if account request is rejected", async () => {
    // Mock a provider that returns an empty array for accounts
    const mockProvider: EIP1193Provider = {
      on: vi.fn(),
      removeListener: vi.fn(),
      request: vi.fn().mockResolvedValue([]) as any,
    };

    await expect(Signer.fromEip1193Provider(mockProvider)).rejects.toThrow(
      "Failed to get address from provider. User may have rejected the request.",
    );
  });
});
