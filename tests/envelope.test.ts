import { describe, it } from "vitest";
import { NucTokenEnvelopeSchema } from "#/envelope";
import { base64UrlDecode, base64UrlEncode } from "#/utils";

const VALID_TOKEN =
  "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAyMjZhNGQ0YTRhNWZhZGUxMmM1ZmYwZWM5YzQ3MjQ5ZjIxY2Y3N2EyMDI3NTFmOTU5ZDVjNzc4ZjBiNjUyYjcxNiIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJhcmdzIjp7ImZvbyI6NDJ9LCJub25jZSI6IjAxMDIwMyIsInByZiI6WyJjOTA0YzVhMWFiMzY5YWVhMWI0ZDlkMTkwMmE0NmU2ZWY5NGFhYjk2OTY0YmI1MWQ2MWE2MWIwM2UyM2Q1ZGZmIl19.ufDYxqoSVNVETrVKReu0h_Piul5c6RoC_VnGGLw04mkyn2OMrtQjK92sGXNHCjlp7T9prIwxX14ZB_N3gx7hPg";

describe("test envelope", () => {
  it("specific token", ({ expect }) => {
    const rawToken =
      "eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAyMjZhNGQ0YTRhNWZhZGUxMmM1ZmYwZWM5YzQ3MjQ5ZjIxY2Y3N2EyMDI3NTFmOTU5ZDVjNzc4ZjBiNjUyYjcxNiIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJhcmdzIjp7ImZvbyI6NDJ9LCJub25jZSI6IjAxMDIwMyIsInByZiI6WyJjOTA0YzVhMWFiMzY5YWVhMWI0ZDlkMTkwMmE0NmU2ZWY5NGFhYjk2OTY0YmI1MWQ2MWE2MWIwM2UyM2Q1ZGZmIl19.ufDYxqoSVNVETrVKReu0h_Piul5c6RoC_VnGGLw04mkyn2OMrtQjK92sGXNHCjlp7T9prIwxX14ZB_N3gx7hPg/eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAzNmY3MDdmYmVmMGI3NTIxMzgwOGJiYmY1NGIxODIxNzZmNTMyMGZhNTIwY2I4MTlmMzViNWJhZjIzMjM4YTAxNSIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJwb2wiOltbIj09IiwiLmZvbyIsNDJdXSwibm9uY2UiOiIwMTAyMDMiLCJwcmYiOlsiODZjZGI1ZjZjN2M3NDFkMDBmNmI4ODMzZDI0ZjdlY2Y5MWFjOGViYzI2MzA3MmZkYmU0YTZkOTQ5NzIwMmNiNCJdfQ.drGzkA0hYP8h62GxNN3fhi9bKjYgjpSy4cM52-9RsyB7JD6O6K1wRsg_x1hv8ladPmChpwDVVXOzjNr2NRVntA/eyJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6bmlsOjAzOTU5MGNjYWYxMDI0ZjQ5YzljZjc0M2Y4YTZlZDQyMDNlNzgyZThlZTA5YWZhNTNkMWI1NzY0OTg0NjEyMzQyNSIsImF1ZCI6ImRpZDpuaWw6YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiIiwic3ViIjoiZGlkOm5pbDpjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2NjY2MiLCJjbWQiOiIvbmlsL2RiL3JlYWQiLCJwb2wiOltbIj09IiwiLmZvbyIsNDJdXSwibm9uY2UiOiIwMTAyMDMiLCJwcmYiOltdfQ.o3lnQxCjDCW10UuRABrHp8FpB_C6q1xgEGvfuXTb7Epp63ry8R2h0wHjToDKDFmkmUmO2jcBkrttuy8kftV6og";
    const token = NucTokenEnvelopeSchema.parse(rawToken);
    token.validateSignatures();
    expect(token.proofs.length).toBe(2);
    expect(token.proofs[0].issuer.publicKey).toStrictEqual(
      new Uint8Array([
        3, 111, 112, 127, 190, 240, 183, 82, 19, 128, 139, 187, 245, 75, 24, 33,
        118, 245, 50, 15, 165, 32, 203, 129, 159, 53, 181, 186, 242, 50, 56,
        160, 21,
      ]),
    );
    expect(token.proofs[1].issuer.publicKey).toStrictEqual(
      new Uint8Array([
        3, 149, 144, 204, 175, 16, 36, 244, 156, 156, 247, 67, 248, 166, 237,
        66, 3, 231, 130, 232, 238, 9, 175, 165, 61, 27, 87, 100, 152, 70, 18,
        52, 37,
      ]),
    );
  });

  it("different signature", ({ expect }) => {
    const [header, payload, _] = VALID_TOKEN.split(".").filter(Boolean);
    const invalidSignature = new Uint8Array(Array(64).fill(1));
    const invalidToken = `${header}.${payload}.${base64UrlEncode(invalidSignature)}`;
    expect(() =>
      NucTokenEnvelopeSchema.parse(invalidToken).validateSignatures(),
    ).toThrowError();
  });

  it("different header", ({ expect }) => {
    const [_, payload, signature] = VALID_TOKEN.split(".").filter(Boolean);
    const invalidHeader = base64UrlEncode('{"alg":"ES256K"} ');
    const invalidToken = `${invalidHeader}.${payload}.${signature}`;
    expect(() =>
      NucTokenEnvelopeSchema.parse(invalidToken).validateSignatures(),
    ).toThrowError();
  });

  it("different payload", ({ expect }) => {
    const [header, payload, signature] = VALID_TOKEN.split(".").filter(Boolean);
    const invalidPayload = base64UrlEncode(`${base64UrlDecode(payload)}  `);
    const invalidToken = `${header}.${invalidPayload}.${signature}`;
    expect(() =>
      NucTokenEnvelopeSchema.parse(invalidToken).validateSignatures(),
    ).toThrowError();
  });
});
