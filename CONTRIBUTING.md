# Contributing

Thanks for contributing to Mac Developer Bridge.

## Before opening a pull request

1. Read `SECURITY.md`. This project intentionally exposes unrestricted local capabilities, so changes to authentication, process containment, credential handling, transports, or tool annotations deserve extra scrutiny.
2. Keep changes focused and avoid adding dependencies unless they are clearly justified.
3. Run the checks locally:

```bash
npm run check
npm test
```

The test suite expects a clean environment. If you are running it from inside an active Mac Developer Bridge session, inherited `MAC_DEV_BRIDGE_*` variables or a live HTTP/Cloudflare transport can interfere with containment tests. Run it from a normal terminal or a clean CI runner.

## Pull requests

Please include:

- what changed and why;
- any security implications;
- tests for behavior changes and bug fixes;
- documentation updates when configuration or operator behavior changes.

Do not include credentials, tokens, local runtime state, generated `MacDevBridge.app` bundles, machine-specific paths, or personal data.

## Security reports

Do not open a public issue for a vulnerability that could expose credentials, bypass authentication, escape containment claims, or broaden remote execution. Use the repository's private GitHub security reporting channel instead.
