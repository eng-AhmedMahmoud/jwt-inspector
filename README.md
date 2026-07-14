# jwt-inspector

> Peek inside a JSON Web Token — safely, in your browser.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/eng-AhmedMahmoud/jwt-inspector/pulls)

A tiny, dependency-free, client-side tool to decode and inspect JSON Web Tokens.

> Live demo: https://jwt.devya.dev

## The problem

Developers constantly need to peek inside a JWT to debug auth — check the claims,
confirm the `exp`, read the `alg`. The usual move is to paste the token into a
random online decoder. That is a real security risk: you have just handed a
credential to a third-party server.

**jwt-inspector decodes and inspects your JWT entirely in the browser.** The token
is parsed with a few lines of vanilla JavaScript and never touches the network.

## Features

- Paste a JWT and instantly see the decoded **header** and **payload** as
  pretty-printed, syntax-highlighted JSON.
- **Claims table** with friendly labels for standard claims (`iss`, `sub`, `aud`,
  `azp`, `scope`, `jti`).
- Time claims (`exp`, `iat`, `nbf`) shown as both the raw epoch and a
  human-readable local date.
- **Expiry status badge** — `valid`, `expired X ago`, or `not yet valid (nbf)` —
  with a live countdown to expiry while the token is valid.
- Signature segment displayed alongside the `alg`, with a clear note that the
  signature is **not** verified (verifying needs the secret/public key).
- **Copy** buttons for the decoded header and payload JSON.
- **Load sample** button that builds a demo token at runtime.
- Graceful, inline errors for malformed tokens.

## Privacy

- **Your token never leaves this browser.** All decoding happens locally.
- **Zero network calls.** No analytics, no backend, no third-party requests.
- The signature is never sent anywhere and is never verified here — verification
  requires your secret or public key, which belongs on your server.

## Run locally

No build step, no dependencies. Either:

```bash
# Just open the file
open index.html
```

or serve it statically:

```bash
npm run dev   # runs: npx --yes serve .
```

## License

GPL-3.0-or-later. See [LICENSE](./LICENSE).

Built by [Devya](https://devya.dev).
