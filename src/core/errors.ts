export class InvalidContentType extends Error {
  public readonly _tag = "InvalidContentType";
  constructor(
    public readonly response: globalThis.Response,
    public override readonly cause: Error,
  ) {
    super(
      `Invalid content type: status=${response.status} url=${response.url} cause=${cause.message}`,
    );
  }
}
