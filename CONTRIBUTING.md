# Contributing

We welcome contributions! Here's how you can get involved:

- 🐛 Report bugs and submit feature requests
- 🔧 Submit pull requests
- 📖 Improve documentation
- 💬 Join discussions
- ⭐ Star the repository

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

## Versioning

The version number format for this library and the changes to the library associated with version number increments conform with [Semantic Versioning 2.0.0](https://semver.org/#semantic-versioning-200).

## Publishing

This library can be published as a [package on npmjs](https://www.npmjs.com/package/@nillion/nuc) via the GitHub Actions workflow.