# Nostr Promenade bunker setup

This small Node.js tool provisions an existing Nostr identity as a distributed 2-of-3 Promenade bunker. It is a command-line workaround for a failed browser-based setup and is not a production-audited key-management product.

For the concepts, key formats, local and distributed bunkers, trust model, and a complete walkthrough, read:
[Nostr from First Principles: Protocol, Relays, and Application Galaxies](https://weisser-zwerg.dev/posts/publishing-nostr-basics/)

## Requirements

- Node.js 24 or newer.
- `nak v0.21.2` for the final signing check.
- An existing Nostr secret stored outside Git in a mode-600 file.
- A secure backup of that secret.

The observed nstart problem and the workaround are recorded here: [failed to get enough signers - ERROR: bad req: provided filter is not an object](https://github.com/dtonon/nstart/issues/42)

## Install and test

```bash
npm ci --ignore-scripts
npm test
node bunker.mjs help
```

The tests use temporary keys and fake relays. They do not provision a bunker.

## Preview

Review `config.json`, then preview the exact identity, signers, relays, and threshold without making network requests:

```bash
node bunker.mjs preview --key-file /ABS/PATH/identity.hex --expect-npub YOUR_NPUB
```

## Provision

Provisioning sends enrollment records to the configured services. Keep the state directory outside every Git checkout; its parent must already exist with mode 700.

```bash
node bunker.mjs provision --key-file /ABS/PATH/identity.hex --expect-npub YOUR_NPUB \
  --state-dir /ABS/PATH/private-state/attempt-1 \
  --key-backed-up \
  --accept-remote-signers \
  --accept-coordinator-ack-only
```

On success, `connection.json` contains the private `bunker://` capability. Protect it like a credential.

Do not blindly repeat a failed provisioning attempt: a signer may have received a share even if its acknowledgement was not observed. Inspect the retained evidence:

```bash
node bunker.mjs status --state-dir /ABS/PATH/private-state/attempt-1
```

After successful provisioning, test remote signing without broadcasting the test event:

```bash
node bunker.mjs sign-check --state-dir /ABS/PATH/private-state/attempt-1 --confirm-remote-sign YOUR_NPUB
```

Use `node bunker.mjs help` and the blog post for the narrowly constrained recovery modes and further explanation.
