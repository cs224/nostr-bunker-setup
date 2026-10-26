import assert from 'node:assert/strict';
import {chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {spawnSync} from 'node:child_process';
import {test} from 'node:test';
import {
  argumentsFor, BunkerError, mine, preview, privateLocation, provision,
  readKey, RelayTransport, safeErrorMessage, signCheck, status, validateConfig,
} from '../bunker.mjs';
import {finalizeEvent, generateSecretKey, getPublicKey, verifyEvent} from '../node_modules/@nostr/tools/pure.js';
import {npubEncode, nsecEncode} from '../node_modules/@nostr/tools/nip19.js';
import {decrypt, getConversationKey} from '../node_modules/@nostr/tools/nip44.js';
import {SimplePool} from '../node_modules/@nostr/tools/pool.js';
import {getPow} from '../node_modules/@nostr/tools/nip13.js';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'publisher-bunker-'));
  t.after(() => rmSync(root, {recursive: true, force: true}));
  const key = generateSecretKey();
  const signerKeys = [generateSecretKey(), generateSecretKey(), generateSecretKey()];
  const config = {schema_version: 1, coordinator: 'wss://coordinator.example.org', threshold: 2,
    reply_relays: ['wss://reply.example.org'], timeout_ms: 1000,
    signers: signerKeys.map(secret => ({pubkey: getPublicKey(secret), inbox_relays: ['wss://inbox.example.org']}))};
  const pubkey = getPublicKey(key);
  const npub = npubEncode(pubkey);
  const keyfile = join(root, 'owner.nsec');
  writeFileSync(keyfile, nsecEncode(key), {mode: 0o600});
  const directory = join(root, 'state');
  const calls = [];
  const publicEvents = [];
  const transport = {
    async enroll(c, signer, request) {
      calls.push(['enroll', signer.pubkey]);
      assert.deepEqual(c, config);
      assert.ok(verifyEvent(request));
      assert.ok(existsSync(join(directory, 'intent.json')));
      const index = config.signers.findIndex(item => item.pubkey === signer.pubkey);
      const active = existsSync(join(directory, 'unsent-recovery')) ? join(directory, 'unsent-recovery') : directory;
      assert.equal(JSON.parse(readFileSync(join(active, `signer-${index + 1}.request.json`))).id, request.id);
      const plaintext = decrypt(request.content, getConversationKey(signerKeys[index], pubkey));
      assert.match(plaintext, /^[0-9a-f]+$/);
      const bytes = Buffer.from(plaintext, 'hex');
      assert.equal(bytes.readUInt16LE(0), index + 1);
      assert.deepEqual(request.tags.find(tag => tag[0] === 'reply'), ['reply', ...config.reply_relays]);
      const ack = finalizeEvent({kind: 26429, created_at: request.created_at,
        tags: [['p', pubkey], ['e', request.id]], content: ''}, signerKeys[index]);
      publicEvents.push(ack);
      return ack;
    },
    async publish(relays, event) {
      calls.push(['publish', relays]);
      assert.equal(event.kind, 16430);
      const active = existsSync(join(directory, 'unsent-recovery')) ? join(directory, 'unsent-recovery') : directory;
      assert.ok(existsSync(join(active, 'connection.json')));
      publicEvents.push(event);
    },
    async find(relays, filter) {
      calls.push(['find', relays]);
      return publicEvents.filter(event => (!filter.ids || filter.ids.includes(event.id)) &&
        (!filter.kinds || filter.kinds.includes(event.kind)) &&
        (!filter.authors || filter.authors.includes(event.pubkey)));
    },
    close() { calls.push(['close']); },
  };
  const options = {key, config, expectedNpub: npub, directory, confirm: npub,
    keyBackedUp: true, acceptRemoteSigners: true, acceptCoordinatorAckOnly: true,
    makeTransport: () => transport,
    // No real PoW/network in lifecycle unit tests; real PoW is tested separately below.
    mineEvent: async unsigned => unsigned};
  return {root, key, keyfile, directory, config, npub, pubkey, options, calls, transport, signerKeys};
}

test('local diagnostics expose only allowlisted filesystem codes, never paths or raw errors', () => {
  const error = Object.assign(new Error('private-key-material'), {
    code: 'ENOENT', syscall: 'open', path: '/private/secret.nsec',
  });
  const message = safeErrorMessage(error);
  assert.match(message, /ENOENT during open/);
  assert.equal(message.includes(error.message), false);
  assert.equal(message.includes(error.path), false);
  assert.equal(safeErrorMessage(new Error('private-key-material')).includes('private-key-material'), false);
});

test('preview validates identity offline without state, shares, signatures, or sockets', t => {
  const f = fixture(t);
  const plan = preview(readKey(f.keyfile), f.config, f.npub);
  assert.equal(plan.pubkey, f.pubkey);
  assert.equal(plan.proof_of_work, 20);
  assert.match(plan.network_actions, /none/);
  assert.equal(existsSync(f.directory), false);
  assert.deepEqual(f.calls, []);
  const text = JSON.stringify(plan);
  assert.equal(text.includes(Buffer.from(f.key).toString('hex')), false);
  assert.throws(() => preview(f.key, f.config, 'npub-wrong'), /expect-npub/);
});

test('private key loading rejects public keys, invalid scalars, symlinks, permissions, Git and build', t => {
  const f = fixture(t);
  for (const value of [f.npub, '0'.repeat(64), 'f'.repeat(64), 'invalid', 'ncryptsec1invalid']) {
    writeFileSync(f.keyfile, value);
    assert.throws(() => readKey(f.keyfile), /valid nsec/);
  }
  writeFileSync(f.keyfile, Buffer.from(f.key).toString('hex'));
  assert.deepEqual(readKey(f.keyfile), f.key);
  chmodSync(f.keyfile, 0o644);
  assert.throws(() => readKey(f.keyfile), /mode 600/);
  chmodSync(f.keyfile, 0o600);
  const alias = join(f.root, 'alias');
  symlinkSync(f.keyfile, alias);
  assert.throws(() => readKey(alias), /symlinks/);
  const repo = join(f.root, 'repo');
  mkdirSync(repo);
  mkdirSync(join(repo, '.git'));
  writeFileSync(join(repo, '.git/HEAD'), 'ref: refs/heads/main\n');
  assert.throws(() => privateLocation(join(repo, 'state'), true), /Git/);
  assert.throws(() => privateLocation(join(f.root, 'build/state'), true), /outside build/);
  assert.throws(() => privateLocation('relative'), /absolute/);
});

test('config rejects ambiguous destinations, duplicates, credentials, and invalid thresholds', t => {
  const f = fixture(t);
  for (const change of [{threshold: 1}, {threshold: 4}, {timeout_ms: 0}, {unexpected: true},
    {coordinator: 'https://example.org'}, {coordinator: 'wss://user:password@example.org'},
    {reply_relays: []}, {reply_relays: ['wss://example.org', 'wss://example.org']},
    {signers: [f.config.signers[0], f.config.signers[0]]}]) {
    assert.throws(() => validateConfig({...f.config, ...change}));
  }
});

test('missing confirmation/backup/remote-signer consent prevents any state or network action', async t => {
  const f = fixture(t);
  for (const change of [{confirm: 'yes'}, {keyBackedUp: false}, {acceptRemoteSigners: false},
    {acceptCoordinatorAckOnly: false}, {expectedNpub: 'wrong'}]) {
    await assert.rejects(provision({...f.options, ...change}));
  }
  assert.deepEqual(f.calls, []);
  assert.equal(existsSync(f.directory), false);
});

test('explicit provisioning saves exact requests before sending and capability before coordinator write', async t => {
  const f = fixture(t);
  const result = await provision(f.options);
  assert.equal(statSync(f.directory).mode & 0o777, 0o700);
  assert.equal(statSync(join(f.directory, 'connection.json')).mode & 0o777, 0o600);
  assert.equal(result.threshold, 2);
  assert.equal(result.signers.length, 3);
  assert.match(result.verification, /not yet tested/);
  const connection = JSON.parse(readFileSync(join(f.directory, 'connection.json')));
  const event = connection.coordinator_event;
  assert.ok(verifyEvent(event));
  assert.equal(event.pubkey, f.pubkey);
  assert.equal(event.tags.filter(tag => tag[0] === 'p').length, 3);
  assert.deepEqual(event.tags.find(tag => tag[0] === 'threshold'), ['threshold', '2']);
  const url = new URL(connection.bunker_url);
  assert.equal(url.hostname, event.tags.find(tag => tag[0] === 'h')[1]);
  assert.equal(url.searchParams.get('secret'), event.tags.find(tag => tag[0] === 'profile')[2]);
  assert.equal(JSON.stringify(result).includes(url.searchParams.get('secret')), false);
  assert.equal(JSON.stringify(result).includes('handlersecret'), false);
  const local = await status(f.directory);
  assert.equal(local.acknowledgements.filter(item => item.found).length, 3);
  const network = await status(f.directory, true, () => f.transport);
  assert.match(network.coordinator_verification, /not queried/);
  assert.equal(network.coordinator_event_id, event.id);
  const calls = f.calls.length;
  await assert.rejects(provision(f.options), /already exists/);
  assert.equal(f.calls.length, calls);
});

test('provisioning never attempts unsupported coordinator reads; publication ACK is explicitly qualified', async t => {
  const f = fixture(t);
  f.transport.find = async () => { throw new Error('Coordinator reads are forbidden'); };
  const result = await provision(f.options);
  assert.match(result.verification, /publication acknowledgement only/);
  await status(f.directory, true, () => ({...f.transport, find: async (relays) => {
    assert.equal(relays.includes(f.config.coordinator), false);
    return [];
  }}));
});

function oldPreflight(f) {
  mkdirSync(f.directory, {mode: 0o700});
  const intent = {...preview(f.key, f.config, f.npub), attempt_id: 'original-attempt'};
  const failure = {stage: 'coordinator-preflight', reason: 'No read-only query relay connected.',
    outcome: 'incomplete-or-uncertain'};
  writeFileSync(join(f.directory, 'intent.json'), JSON.stringify(intent), {mode: 0o600});
  writeFileSync(join(f.directory, 'failure.json'), JSON.stringify(failure), {mode: 0o600});
  return {intent: readFileSync(join(f.directory, 'intent.json')), failure: readFileSync(join(f.directory, 'failure.json'))};
}

test('explicit continuation preserves old intent/failure bytes and can enroll only once', async t => {
  const f = fixture(t);
  const before = oldPreflight(f);
  await assert.rejects(provision(f.options), /already exists/);
  const result = await provision({...f.options, resumePreflight: true});
  assert.match(result.verification, /remote signing not yet tested/);
  assert.deepEqual(readFileSync(join(f.directory, 'intent.json')), before.intent);
  assert.deepEqual(readFileSync(join(f.directory, 'failure.json')), before.failure);
  assert.ok(existsSync(join(f.directory, 'preflight-continuation.json')));
  const calls = f.calls.length;
  await assert.rejects(provision({...f.options, resumePreflight: true}), /ONLY the original/);
  assert.equal(f.calls.length, calls);
});

test('continuation refuses unknown failures, config/identity changes, and any share/coordinator evidence', async t => {
  for (const change of ['stage', 'reason', 'config', 'identity', 'request', 'connection', 'marker']) {
    const f = fixture(t);
    oldPreflight(f);
    if (change === 'stage' || change === 'reason') {
      const failure = JSON.parse(readFileSync(join(f.directory, 'failure.json')));
      failure[change] = change === 'stage' ? 'signer-1' : 'An existing coordinator setup was found.';
      writeFileSync(join(f.directory, 'failure.json'), JSON.stringify(failure));
    } else if (change === 'config' || change === 'identity') {
      const intent = JSON.parse(readFileSync(join(f.directory, 'intent.json')));
      if (change === 'config') intent.config.threshold = 3;
      else intent.pubkey = getPublicKey(generateSecretKey());
      writeFileSync(join(f.directory, 'intent.json'), JSON.stringify(intent));
    } else {
      const file = {request: 'signer-1.request.json', connection: 'connection.json', marker: 'preflight-continuation.json'}[change];
      writeFileSync(join(f.directory, file), '{}', {mode: 0o600});
    }
    await assert.rejects(provision({...f.options, resumePreflight: true}), /Continuation requires|not a matching/);
    assert.deepEqual(f.calls, []);
  }
});

test('failed continuation appends new failure without overwriting the old one or allowing resend', async t => {
  const f = fixture(t);
  const before = oldPreflight(f);
  f.transport.enroll = async () => { throw new Error('failure'); };
  await assert.rejects(provision({...f.options, resumePreflight: true}), /signer-1/);
  assert.deepEqual(readFileSync(join(f.directory, 'failure.json')), before.failure);
  assert.ok(existsSync(join(f.directory, 'continuation.failure.json')));
  await assert.rejects(provision({...f.options, resumePreflight: true}), /ONLY the original/);
});

test('known first-share unsent failure recovers into a child without modifying original evidence', async t => {
  const f = fixture(t);
  const original = f.transport.enroll;
  f.transport.enroll = async () => { throw new BunkerError('No reply relay connected; no share sent to this signer.'); };
  oldPreflight(f);
  await assert.rejects(provision({...f.options, resumePreflight: true}), /no share sent/);
  const names = ['intent.json', 'failure.json', 'preflight-continuation.json', 'continuation.failure.json', 'signer-1.request.json'];
  const before = names.map(name => readFileSync(join(f.directory, name)));
  f.transport.enroll = original;
  const result = await provision({...f.options, resumeUnsent: true});
  assert.equal(result.connection_file, join(f.directory, 'unsent-recovery/connection.json'));
  for (const [index, name] of names.entries()) assert.deepEqual(readFileSync(join(f.directory, name)), before[index]);
  const intent = JSON.parse(readFileSync(join(f.directory, 'unsent-recovery/intent.json')));
  assert.equal(intent.previous_unsent_attempt, f.directory);
  await assert.rejects(provision({...f.options, resumeUnsent: true}), /Unsent recovery requires/);
});

test('unsent recovery rejects uncertain sends, extra ACK evidence and conflicting continuation flags', async t => {
  for (const change of ['uncertain', 'ack', 'both-flags']) {
    const f = fixture(t);
    f.transport.enroll = async () => { throw new BunkerError('No reply relay connected; no share sent to this signer.'); };
    await assert.rejects(provision(f.options), /no share sent/);
    if (change === 'uncertain') {
      const failure = JSON.parse(readFileSync(join(f.directory, 'failure.json')));
      failure.reason = 'Signer acknowledgement timed out.';
      writeFileSync(join(f.directory, 'failure.json'), JSON.stringify(failure));
    } else if (change === 'ack') writeFileSync(join(f.directory, 'signer-1.ack.json'), '{}', {mode: 0o600});
    const calls = f.calls.length;
    await assert.rejects(provision({...f.options, resumeUnsent: true, resumePreflight: change === 'both-flags'}));
    assert.equal(f.calls.length, calls);
    assert.equal(existsSync(join(f.directory, 'unsent-recovery')), false);
  }
});

test('timeouts, wrong signatures/authors/tags stop enrollment; no coordinator publication or blind retry', async t => {
  for (const failure of ['timeout', 'wrong-author', 'wrong-reference', 'bad-signature']) {
    const f = fixture(t);
    f.transport.enroll = async (_, signer, request) => {
      if (failure === 'timeout') throw new Error('raw-secret-output-must-not-escape');
      const ack = finalizeEvent({kind: 26429, created_at: 1,
        tags: [['p', f.pubkey], ['e', failure === 'wrong-reference' ? '0'.repeat(64) : request.id]], content: ''},
      failure === 'wrong-author' ? f.key : f.signerKeys[0]);
      if (failure === 'bad-signature') ack.sig = '0'.repeat(128);
      return JSON.parse(JSON.stringify(ack));
    };
    await assert.rejects(provision(f.options), error => {
      assert.equal(error.message.includes('raw-secret-output'), false);
      return /signer-1/.test(error.message);
    });
    assert.ok(existsSync(join(f.directory, 'failure.json')));
    assert.equal(existsSync(join(f.directory, 'connection.json')), false);
    assert.equal(f.calls.some(([name]) => name === 'publish'), false);
    await assert.rejects(provision(f.options), /already exists/);
  }
});

test('coordinator timeout retains private connection and does not claim success', async t => {
  const f = fixture(t);
  f.transport.publish = async () => { throw new Error('sensitive coordinator response'); };
  await assert.rejects(provision(f.options), /coordinator/);
  assert.ok(existsSync(join(f.directory, 'connection.json')));
  assert.equal(existsSync(join(f.directory, 'receipt.json')), false);
  assert.equal((await status(f.directory)).local_receipt, false);
});

test('wire REQ contains object filters and rejected subscriptions fail immediately, not as signer timeouts', async () => {
  const frames = [];
  class FakeWebSocket {
    constructor(url) { this.url = url; queueMicrotask(() => this.onopen?.()); }
    send(text) {
      const frame = JSON.parse(text);
      frames.push(frame);
      if (frame[0] === 'REQ') {
        assert.equal(Array.isArray(frame[2]), false);
        assert.deepEqual(frame[2].kinds, [26429]);
        queueMicrotask(() => this.onmessage?.({data: JSON.stringify(['CLOSED', frame[1], 'bad req'])}));
      } else if (frame[0] === 'EVENT') {
        queueMicrotask(() => this.onmessage?.({data: JSON.stringify(['OK', frame[1].id, true, ''])}));
      }
    }
    close() { this.onclose?.({message: 'closed'}); }
  }
  const key = generateSecretKey();
  const signer = getPublicKey(generateSecretKey());
  const request = finalizeEvent({kind: 26428, created_at: 1, tags: [], content: ''}, key);
  const pool = new SimplePool({websocketImplementation: FakeWebSocket});
  const transport = new RelayTransport(pool);
  try {
    await assert.rejects(transport.enroll({reply_relays: ['wss://reply.example.org'], timeout_ms: 1000},
      {pubkey: signer, inbox_relays: ['wss://inbox.example.org']}, request), /subscription closed/);
    assert.ok(frames.some(frame => frame[0] === 'REQ'));
  } finally { transport.close(); }
});

test('read-only preflight distinguishes rejected subscriptions from an empty completed query', async () => {
  for (const reply of ['CLOSED', 'EOSE']) {
    class FakeWebSocket {
      constructor() { queueMicrotask(() => this.onopen?.()); }
      send(text) {
        const frame = JSON.parse(text);
        if (frame[0] === 'REQ') {
          assert.equal(Array.isArray(frame[2]), false);
          queueMicrotask(() => this.onmessage?.({data: JSON.stringify([reply, frame[1], 'rejected'])}));
        }
      }
      close() { this.onclose?.({message: 'closed'}); }
    }
    const transport = new RelayTransport(new SimplePool({websocketImplementation: FakeWebSocket}));
    try {
      const query = transport.find(['wss://coordinator.example.org'], {kinds: [16430]}, 1000);
      if (reply === 'CLOSED') await assert.rejects(query, /closed\/rejected/);
      else assert.deepEqual(await query, []);
    } finally { transport.close(); }
  }
});

test('real pinned pool receives a signed enrollment acknowledgement over the corrected wire subscription', async () => {
  const owner = generateSecretKey();
  const signerKey = generateSecretKey();
  const signer = getPublicKey(signerKey);
  const sockets = [];
  let requestFilter;
  class FakeWebSocket {
    constructor() { sockets.push(this); queueMicrotask(() => this.onopen?.()); }
    send(text) {
      const frame = JSON.parse(text);
      if (frame[0] === 'REQ') {
        requestFilter = frame[2];
        assert.equal(Array.isArray(requestFilter), false);
        this.subscription = frame[1];
      } else if (frame[0] === 'EVENT') {
        const event = frame[1];
        assert.equal(requestFilter['#e'][0], event.id);
        const ack = finalizeEvent({kind: 26429, created_at: 1,
          tags: [['p', event.pubkey], ['e', event.id]], content: ''}, signerKey);
        queueMicrotask(() => {
          this.onmessage?.({data: JSON.stringify(['OK', event.id, true, ''])});
          for (const socket of sockets) {
            if (socket.subscription) socket.onmessage?.({data: JSON.stringify(['EVENT', socket.subscription, ack])});
          }
        });
      }
    }
    close() { this.onclose?.({message: 'closed'}); }
  }
  const transport = new RelayTransport(new SimplePool({websocketImplementation: FakeWebSocket}));
  try {
    const request = finalizeEvent({kind: 26428, created_at: 1, tags: [], content: ''}, owner);
    const ack = await transport.enroll({reply_relays: ['wss://reply.example.org'], timeout_ms: 1000},
      {pubkey: signer, inbox_relays: ['wss://inbox.example.org']}, request);
    assert.equal(ack.pubkey, signer);
    assert.ok(verifyEvent(ack));
  } finally { transport.close(); }
});

test('nak handoff passes capability via environment and no publication relays; verifies returned owner signature', async t => {
  const f = fixture(t);
  await provision(f.options);
  const calls = [];
  const run = (command, args, options) => {
    calls.push([command, args, options]);
    if (args[0] === '--version') return {status: 0, stdout: 'nak version v0.21.2\n'};
    const content = args[args.indexOf('--content') + 1];
    return {status: 0, stdout: JSON.stringify(finalizeEvent({kind: 1, created_at: 1, tags: [], content}, f.key))};
  };
  assert.throws(() => signCheck(f.directory, 'wrong', run), /confirm-remote-sign/);
  assert.equal(calls.length, 0);
  const result = signCheck(f.directory, f.npub, run);
  assert.equal(result.signature_validation, 'passed');
  assert.match(result.network_actions, /not broadcast/);
  assert.equal(calls[1][2].stdio[0], 'ignore');
  assert.ok(calls[1][2].env.NOSTR_SECRET_KEY.startsWith('bunker://'));
  assert.equal(calls[1][1].some(arg => /^(wss:|bunker:)/.test(arg)), false);
  assert.throws(() => signCheck(f.directory, f.npub, () => ({status: 1, stdout: 'secret'})), /nak v0.21.2/);
});

test('CLI rejects unknown/duplicate/wrong-command flags, and preview never creates state', t => {
  const f = fixture(t);
  for (const argv of [['publish'], ['preview', '--query-relays'], ['status', '--state-dir'],
    ['preview', '--key-file', 'one', '--key-file', 'two']]) assert.throws(() => argumentsFor(argv));
  const configPath = join(f.root, 'config.json');
  writeFileSync(configPath, JSON.stringify(f.config));
  const result = spawnSync('node', ['bunker.mjs', 'preview',
    '--key-file', f.keyfile, '--expect-npub', f.npub, '--config', configPath], {encoding: 'utf8', timeout: 10000});
  assert.equal(result.status, 0, result.stderr);
  assert.equal(JSON.parse(result.stdout).npub, f.npub);
  assert.equal(result.stdout.includes(nsecEncode(f.key)), false);
  assert.equal(existsSync(f.directory), false);
});

test('proof of work runs in the worker with upstream hashing; fast small-difficulty check', async () => {
  const key = generateSecretKey();
  const unsigned = {pubkey: getPublicKey(key), kind: 26428, created_at: 1, tags: [], content: 'encrypted-test-envelope'};
  const mined = await mine(unsigned, 4);
  assert.ok(getPow(mined.id) >= 4);
  assert.deepEqual(mined.tags.find(tag => tag[0] === 'nonce').slice(2), ['4']);
  assert.ok(verifyEvent(finalizeEvent(mined, key)));
  assert.equal(unsigned.tags.length, 0);
});

test('worker does not inherit the parent CLI --input-type flag', () => {
  const result = spawnSync('node', ['--input-type=module', '-e',
    'import {mine} from "./bunker.mjs"; ' +
    'await mine({pubkey:"f".repeat(64),kind:26428,created_at:1,tags:[],content:"dummy"},4); console.log("passed");'],
  {encoding: 'utf8', timeout: 10000});
  assert.equal(result.error, undefined);
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout.trim(), 'passed');
});
