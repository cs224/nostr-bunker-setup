// Standalone Promenade provisioning helper; importing this module opens no sockets and reads no private key.
import {
  closeSync, constants, existsSync, fstatSync, fsyncSync, lstatSync, mkdirSync,
  openSync, readFileSync, readdirSync, writeFileSync,
} from 'node:fs';
import {randomBytes, randomUUID} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import {dirname, isAbsolute, join, parse, resolve, sep} from 'node:path';
import {pathToFileURL} from 'node:url';
import {Worker} from 'node:worker_threads';
import {isDeepStrictEqual} from 'node:util';
import {trustedKeyDeal, hexShard, hexPubShard} from '@fiatjaf/promenade-trusted-dealer';
import {finalizeEvent, generateSecretKey, getEventHash, getPublicKey, verifyEvent} from '@nostr/tools/pure';
import {decode, npubEncode} from '@nostr/tools/nip19';
import {encrypt, getConversationKey} from '@nostr/tools/nip44';
import {SimplePool} from '@nostr/tools/pool';

export class BunkerError extends Error {}
export function safeErrorMessage(error) {
  if (error instanceof BunkerError) return error.message;
  if (['ENOENT', 'EACCES', 'EPERM', 'EEXIST', 'ENOTDIR', 'ELOOP', 'ENOSPC', 'EROFS'].includes(error?.code)) {
    const operation = ['open', 'mkdir', 'lstat', 'read', 'write', 'fsync'].includes(error.syscall)
      ? ` during ${error.syscall}` : '';
    return `Local filesystem error: ${error.code}${operation}. Check the key/config paths and the existing parent of --state-dir. Private contents suppressed; inspect existing attempt state before retrying.`;
  }
  return 'Local setup failed; sensitive error details suppressed.';
}
const HEX = /^[0-9a-f]{64}$/;
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const DEPENDENCIES = {dealer: '0.4.3', nostr_tools: '2.16.2', nak: 'v0.21.2'};
const DEFAULT_CONFIG = new URL('./config.json', import.meta.url);

export function validateConfig(config) {
  const allowed = ['schema_version', 'coordinator', 'threshold', 'reply_relays', 'timeout_ms', 'signers'];
  if (!config || Object.keys(config).some(key => !allowed.includes(key)) ||
      config.schema_version !== 1 || !Array.isArray(config.signers) ||
      config.signers.length < 2 || config.signers.length > 6 ||
      !Number.isInteger(config.threshold) || config.threshold < 2 ||
      config.threshold > config.signers.length || !Number.isInteger(config.timeout_ms) ||
      config.timeout_ms < 1000 || config.timeout_ms > 60000) {
    throw new BunkerError('Invalid provisioning configuration.');
  }
  const relay = value => {
    let url;
    try { url = new URL(value); } catch { throw new BunkerError('Invalid relay URL.'); }
    if (typeof value !== 'string' || url.protocol !== 'wss:' || url.username || url.password ||
        url.hash || url.search) throw new BunkerError('Use explicit wss:// relay URLs without credentials.');
  };
  const relays = values => {
    if (!Array.isArray(values) || !values.length || values.length > 8 ||
        new Set(values).size !== values.length) throw new BunkerError('Invalid relay list.');
    values.forEach(relay);
  };
  relay(config.coordinator);
  relays(config.reply_relays);
  const keys = new Set();
  for (const signer of config.signers) {
    if (!signer || Object.keys(signer).some(key => !['pubkey', 'inbox_relays'].includes(key)) ||
        !HEX.test(signer.pubkey) || keys.has(signer.pubkey)) {
      throw new BunkerError('Signer keys must be distinct lowercase public hex keys.');
    }
    keys.add(signer.pubkey);
    relays(signer.inbox_relays);
  }
  return structuredClone(config);
}

export function privateLocation(path, directory = false) {
  if (!isAbsolute(path) || path !== resolve(path) || path.split(sep).includes('build')) {
    throw new BunkerError('Private paths must be absolute, normalized, and outside build/.');
  }
  for (let current = path; ; current = dirname(current)) {
    const git = join(current, '.git');
    if (existsSync(git) && (!lstatSync(git).isDirectory() || existsSync(join(git, 'HEAD')))) {
      throw new BunkerError('Private state must stay outside Git checkouts.');
    }
    try {
      const stat = lstatSync(current);
      if (stat.isSymbolicLink()) throw new BunkerError('Private paths cannot contain symlinks.');
      if (current === path) {
        if ((directory ? !stat.isDirectory() : !stat.isFile()) || (stat.mode & 0o077) ||
            (process.getuid && stat.uid !== process.getuid())) {
          throw new BunkerError('Private files need mode 600; private directories need mode 700 and your ownership.');
        }
      } else if (!stat.isDirectory()) throw new BunkerError('Invalid private parent directory.');
    } catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (current === parse(current).root) break;
  }
}

export function readPrivate(file) {
  privateLocation(file);
  const fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || (stat.mode & 0o077) || stat.size > 1024 * 1024 ||
        (process.getuid && stat.uid !== process.getuid())) throw new BunkerError('Unsafe private file.');
    return readFileSync(fd, 'utf8');
  } finally { closeSync(fd); }
}

export function readKey(file) {
  const value = readPrivate(file).trim();
  let key;
  try {
    if (HEX.test(value)) key = Uint8Array.from(Buffer.from(value, 'hex'));
    else {
      const decoded = decode(value);
      if (decoded.type !== 'nsec') throw new Error();
      key = decoded.data;
    }
    const scalar = BigInt('0x' + Buffer.from(key).toString('hex'));
    if (key.length !== 32 || scalar <= 0n || scalar >= ORDER) throw new Error();
    getPublicKey(key);
  } catch { throw new BunkerError('Key file must contain a valid nsec or 64-character private hex key.'); }
  return key;
}

function syncDirectory(path) {
  const fd = openSync(path, 'r');
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

export function savePrivate(directory, name, value) {
  privateLocation(directory, true);
  const fd = openSync(join(directory, name), 'wx', 0o600);
  try {
    writeFileSync(fd, JSON.stringify(value, null, 2) + '\n');
    fsyncSync(fd);
  } finally { closeSync(fd); }
  syncDirectory(directory);
}

export function preview(key, config, expectedNpub) {
  config = validateConfig(config);
  const pubkey = getPublicKey(key);
  const npub = npubEncode(pubkey);
  if (expectedNpub !== npub) throw new BunkerError('--expect-npub must match the key; no action taken.');
  if (config.signers.some(signer => signer.pubkey === pubkey)) {
    throw new BunkerError('The owner cannot also be a remote signer candidate.');
  }
  return {schema_version: 1, kind: 'promenade-provisioning-plan', pubkey, npub,
    config, dependencies: DEPENDENCIES, proof_of_work: 20,
    network_actions: 'none; offline preview',
    warning: 'All selected signers must enroll. A threshold can collude to sign/reconstruct the key. ' +
      'A successor setup does not prove old shares were deleted. MAIN grants unrestricted signing. ' +
      'Coordinator verification is publication-acknowledgement only; existing remote setups cannot be checked.'};
}

export function mine(unsigned, difficulty = 20) {
  return new Promise((resolveWork, reject) => {
    const worker = new Worker(new URL('./pow-worker.mjs', import.meta.url), {
      workerData: {unsigned, difficulty},
      // This worker needs no CLI flags (some test-runner/input-type/TLS flags are invalid here).
      execArgv: [],
    });
    const timer = setTimeout(() => {
      worker.terminate();
      reject(new BunkerError('Proof-of-work deadline exceeded.'));
    }, 120000);
    worker.once('message', result => { clearTimeout(timer); resolveWork(result); });
    worker.once('error', () => { clearTimeout(timer); reject(new BunkerError('Proof-of-work failed.')); });
    worker.once('exit', code => {
      clearTimeout(timer);
      if (code !== 0) reject(new BunkerError('Proof-of-work stopped.'));
    });
  });
}

function validEvent(event) {
  try { return getEventHash(event) === event.id && verifyEvent(event); } catch { return false; }
}

function tagged(event, name, value) {
  return event.tags.some(tag => tag[0] === name && tag[1] === value);
}

export function matchesAcknowledgement(event, request, signer) {
  return validEvent(event) && event.kind === 26429 && event.pubkey === signer &&
    tagged(event, 'p', request.pubkey) && tagged(event, 'e', request.id);
}

function bounded(promise, milliseconds, message) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new BunkerError(message)), milliseconds);
  })]).finally(() => clearTimeout(timer));
}

export class RelayTransport {
  constructor(pool = new SimplePool()) { this.pool = pool; }

  async publish(relays, event, timeout) {
    try {
      await bounded(Promise.any(this.pool.publish(relays, event)), timeout, 'Relay publication timed out.');
    } catch (error) {
      if (error instanceof BunkerError) throw error;
      throw new BunkerError('All selected relays rejected or failed to accept the event.');
    }
  }

  async enroll(config, signer, request) {
    // Ensure REQ sockets are open first. The subscription uses a FILTER OBJECT, not [filter].
    const open = await Promise.allSettled(config.reply_relays.map(url =>
      this.pool.ensureRelay(url, {connectionTimeout: 5000})));
    const relays = config.reply_relays.filter((_, index) => open[index].status === 'fulfilled');
    if (!relays.length) throw new BunkerError('No reply relay connected; no share sent to this signer.');
    let subscription;
    try {
      const ack = new Promise((resolveAck, reject) => {
        subscription = this.pool.subscribe(relays, {
          kinds: [26429], authors: [signer.pubkey], '#p': [request.pubkey], '#e': [request.id],
        }, {
          onevent: event => {
            if (matchesAcknowledgement(event, request, signer.pubkey)) resolveAck(event);
          },
          onclose: () => reject(new BunkerError('Reply subscription closed/rejected; no valid acknowledgement.')),
        });
      });
      // Attach rejection handlers before sending; do not leave an unhandled promise on rejection.
      const result = bounded(ack, config.timeout_ms, 'Signer acknowledgement timed out.');
      const published = this.publish(signer.inbox_relays, request, config.timeout_ms);
      return (await Promise.all([result, published]))[0];
    } finally { await subscription?.close(); }
  }

  async find(relays, filter, timeout) {
    // querySync otherwise collapses CLOSED/connection failures into an empty result, which
    // must not be mistaken for proof that there is no previous coordinator setup.
    const open = await Promise.allSettled(relays.map(url =>
      this.pool.ensureRelay(url, {connectionTimeout: 5000})));
    const connected = relays.filter((_, index) => open[index].status === 'fulfilled');
    if (!connected.length) throw new BunkerError('No read-only query relay connected.');
    let subscription;
    try {
      return await bounded(new Promise((resolveEvents, reject) => {
        const events = [];
        subscription = this.pool.subscribe(connected, filter, {
          // Our deadline fires before the library can manufacture EOSE on its own timeout.
          maxWait: timeout + 2000,
          onevent: event => { if (validEvent(event)) events.push(event); },
          oneose: () => queueMicrotask(() => resolveEvents(events)),
          // The pool invokes oneose before onclose; deferred resolution lets rejection win.
          onclose: () => reject(new BunkerError('Read-only relay query was closed/rejected.')),
        });
      }), timeout, 'Read-only relay query timed out.');
    } finally { await subscription?.close(); }
  }

  close() { this.pool.destroy(); }
}

export async function provision(options) {
  const {key, config, expectedNpub, directory, confirm, keyBackedUp,
    acceptRemoteSigners, acceptCoordinatorAckOnly, resumePreflight = false, resumeUnsent = false,
    makeTransport = () => new RelayTransport(), mineEvent = mine, progress = () => {}} = options;
  const plan = preview(key, config, expectedNpub);
  if (confirm !== plan.npub || !keyBackedUp || !acceptRemoteSigners) {
    throw new BunkerError('Provision requires exact --confirm-provision, --key-backed-up, and --accept-remote-signers.');
  }
  if (acceptCoordinatorAckOnly !== true) {
    throw new BunkerError('Provision requires --accept-coordinator-ack-only: existing remote setups cannot be checked; publication acknowledgement is not a signing test.');
  }
  privateLocation(directory, true);
  if (resumeUnsent) {
    if (resumePreflight) throw new BunkerError('Choose only one continuation mode.');
    const names = readdirSync(directory).sort();
    const continued = names.includes('preflight-continuation.json');
    const allowed = continued
      ? ['continuation.failure.json', 'failure.json', 'intent.json', 'preflight-continuation.json', 'signer-1.request.json']
      : ['failure.json', 'intent.json', 'signer-1.request.json'];
    if (!isDeepStrictEqual(names, allowed)) {
      throw new BunkerError('Unsent recovery requires exactly the saved first request and known failure evidence, with no acknowledgements or earlier recovery.');
    }
    const intent = JSON.parse(readPrivate(join(directory, 'intent.json')));
    const failure = JSON.parse(readPrivate(join(directory, continued ? 'continuation.failure.json' : 'failure.json')));
    const request = JSON.parse(readPrivate(join(directory, 'signer-1.request.json')));
    if (intent.schema_version !== 1 || intent.kind !== 'promenade-provisioning-plan' ||
        intent.pubkey !== plan.pubkey || intent.npub !== plan.npub ||
        !isDeepStrictEqual(intent.config, plan.config) || failure.stage !== 'signer-1' ||
        failure.reason !== 'No reply relay connected; no share sent to this signer.' ||
        failure.outcome !== 'incomplete-or-uncertain' || !validEvent(request) ||
        request.pubkey !== plan.pubkey || request.kind !== 26428 ||
        !tagged(request, 'p', config.signers[0].pubkey) || !tagged(request, 'coordinator', config.coordinator)) {
      throw new BunkerError('Saved attempt does not establish a matching first-share connection failure before send.');
    }
    // No old share left the process. Make a new polynomial in an exclusive child attempt,
    // preserving every original byte. Unknown timeouts or partial sends NEVER enter this path.
    return provision({...options, directory: join(directory, 'unsent-recovery'),
      resumeUnsent: false, previousAttempt: directory});
  }
  if (resumePreflight) {
    const names = readdirSync(directory).sort();
    if (!isDeepStrictEqual(names, ['failure.json', 'intent.json'])) {
      throw new BunkerError('Continuation requires ONLY the original intent and preflight failure; no requests or other attempt files.');
    }
    const intent = JSON.parse(readPrivate(join(directory, 'intent.json')));
    const failure = JSON.parse(readPrivate(join(directory, 'failure.json')));
    const reasons = ['No read-only query relay connected.', 'Read-only relay query was closed/rejected.',
      'Read-only relay query timed out.'];
    if (intent.schema_version !== 1 || intent.kind !== 'promenade-provisioning-plan' ||
        intent.pubkey !== plan.pubkey || intent.npub !== plan.npub ||
        !isDeepStrictEqual(intent.config, plan.config) || failure.stage !== 'coordinator-preflight' ||
        failure.outcome !== 'incomplete-or-uncertain' || !reasons.includes(failure.reason)) {
      throw new BunkerError('Saved attempt is not a matching, known pre-share coordinator-query failure.');
    }
    // Exclusive marker is also a concurrent-continuation guard. Original evidence is untouched.
    savePrivate(directory, 'preflight-continuation.json', {recorded_at: new Date().toISOString(),
      pubkey: plan.pubkey, previous_attempt_id: intent.attempt_id,
      consents: {key_backed_up: true, remote_signers: true, coordinator_ack_only: true},
      reason: 'Continue a known failed read-only preflight; no shares were sent by that attempt.'});
  } else {
    if (existsSync(directory)) throw new BunkerError('State directory already exists. Inspect status; never retry blindly.');
    // Parent must exist, so directory creation/exclusivity is an unambiguous, durable operation.
    mkdirSync(directory, {mode: 0o700});
    syncDirectory(dirname(directory));
    savePrivate(directory, 'intent.json', {...plan, attempt_id: randomUUID(),
      ...(options.previousAttempt ? {previous_unsent_attempt: options.previousAttempt} : {}),
      recorded_at: new Date().toISOString(),
      consents: {key_backed_up: true, remote_signers: true, coordinator_ack_only: true},
      network_actions: 'explicitly authorized provisioning'});
  }
  let transport;
  let stage = 'local-preparation';
  try {
    const {shards} = trustedKeyDeal(BigInt('0x' + Buffer.from(key).toString('hex')),
      config.threshold, config.signers.length);
    const enrolled = [];
    transport = makeTransport();
    for (const [index, signer] of config.signers.entries()) {
      stage = `signer-${index + 1}`;
      progress({stage, signer: signer.pubkey, status: 'preparing'});
      const unsigned = {
        pubkey: plan.pubkey, created_at: Math.floor(Date.now() / 1000), kind: 26428,
        tags: [['p', signer.pubkey], ['coordinator', config.coordinator], ['reply', ...config.reply_relays]],
        content: encrypt(hexShard(shards[index]), getConversationKey(key, signer.pubkey)),
      };
      const request = finalizeEvent(await mineEvent(unsigned), key);
      // Record exact signed requests before external writes; never regenerate on a timeout.
      savePrivate(directory, `${stage}.request.json`, request);
      const ack = await transport.enroll(config, signer, request);
      if (!matchesAcknowledgement(ack, request, signer.pubkey)) throw new BunkerError('Invalid signer acknowledgement.');
      savePrivate(directory, `${stage}.ack.json`, ack);
      enrolled.push(['p', signer.pubkey, hexPubShard(shards[index].pubShard)]);
      progress({stage, signer: signer.pubkey, status: 'acknowledged'});
    }
    const handler = generateSecretKey();
    const handlerPubkey = getPublicKey(handler);
    const connectionSecret = randomBytes(24).toString('hex');
    const coordinatorEvent = finalizeEvent({kind: 16430, created_at: Math.floor(Date.now() / 1000),
      tags: [...enrolled, ['threshold', String(config.threshold)],
        ['handlersecret', Buffer.from(handler).toString('hex')], ['h', handlerPubkey],
        ['profile', 'MAIN', connectionSecret, '']], content: ''}, key);
    const url = new URL(`bunker://${handlerPubkey}`);
    url.searchParams.set('relay', config.coordinator);
    url.searchParams.set('secret', connectionSecret);
    stage = 'coordinator';
    // Includes signing capability: private file ONLY, never stdout or a public receipt.
    savePrivate(directory, 'connection.json', {schema_version: 1, npub: plan.npub,
      pubkey: plan.pubkey, bunker_url: url.toString(), coordinator_event: coordinatorEvent});
    await transport.publish([config.coordinator], coordinatorEvent, config.timeout_ms);
    const receipt = {schema_version: 1, kind: 'promenade-provisioning-receipt', npub: plan.npub,
      pubkey: plan.pubkey, coordinator: config.coordinator, coordinator_event_id: coordinatorEvent.id,
      threshold: config.threshold, signers: config.signers.map(signer => signer.pubkey),
      verification: 'signed signer acknowledgements and coordinator publication acknowledgement only; remote signing not yet tested',
      recorded_at: new Date().toISOString()};
    savePrivate(directory, 'receipt.json', receipt);
    return {...receipt, connection_file: join(directory, 'connection.json')};
  } catch (error) {
    const reason = error instanceof BunkerError ? error.message : 'Unexpected failure; sensitive details suppressed.';
    savePrivate(directory, resumePreflight ? 'continuation.failure.json' : 'failure.json', {stage, reason, outcome: 'incomplete-or-uncertain',
      instruction: 'Keep all evidence. Query status; do not rerun provisioning into this or a new directory blindly.'});
    throw new BunkerError(`Provisioning stopped at ${stage}: ${reason} Private evidence retained; use status, not another attempt.`);
  } finally { transport?.close(); }
}

export async function status(directory, queryRelays = false, makeTransport = () => new RelayTransport()) {
  privateLocation(directory, true);
  const intent = JSON.parse(readPrivate(join(directory, 'intent.json')));
  const config = validateConfig(intent.config);
  if (!HEX.test(intent.pubkey) || npubEncode(intent.pubkey) !== intent.npub) throw new BunkerError('Invalid saved identity.');
  const result = {npub: intent.npub, local_receipt: existsSync(join(directory, 'receipt.json')),
    acknowledgements: [], coordinator_verification: 'not queried; coordinator does not support unsigned record reads',
    network_actions: queryRelays ? 'read-only queries; no signing or publication' : 'none; local inspection'};
  let transport;
  try {
    if (queryRelays) transport = makeTransport();
    for (const [index, signer] of config.signers.entries()) {
      const path = join(directory, `signer-${index + 1}.request.json`);
      if (!existsSync(path)) continue;
      const request = JSON.parse(readPrivate(path));
      if (!validEvent(request) || request.pubkey !== intent.pubkey || request.kind !== 26428 ||
          !tagged(request, 'p', signer.pubkey)) throw new BunkerError('Invalid saved enrollment request.');
      const ackFile = join(directory, `signer-${index + 1}.ack.json`);
      const events = queryRelays ? await transport.find(config.reply_relays,
        {kinds: [26429], authors: [signer.pubkey], '#p': [intent.pubkey], '#e': [request.id]}, config.timeout_ms)
        : existsSync(ackFile) ? [JSON.parse(readPrivate(ackFile))] : [];
      result.acknowledgements.push({signer: signer.pubkey, request_id: request.id,
        found: events.some(event => matchesAcknowledgement(event, request, signer.pubkey))});
    }
    const connectionFile = join(directory, 'connection.json');
    if (existsSync(connectionFile)) {
      const {coordinator_event: event} = JSON.parse(readPrivate(connectionFile));
      if (!validEvent(event) || event.pubkey !== intent.pubkey || event.kind !== 16430) {
        throw new BunkerError('Invalid saved coordinator event.');
      }
      result.coordinator_event_id = event.id;
    }
    return result;
  } finally { transport?.close(); }
}

export function signCheck(directory, confirm, run = spawnSync) {
  const connection = JSON.parse(readPrivate(join(directory, 'connection.json')));
  const receipt = JSON.parse(readPrivate(join(directory, 'receipt.json')));
  if (confirm !== receipt.npub || connection.npub !== receipt.npub ||
      connection.pubkey !== receipt.pubkey ||
      connection.coordinator_event?.id !== receipt.coordinator_event_id) {
    throw new BunkerError('Sign check requires a completed matching receipt and exact --confirm-remote-sign.');
  }
  const version = run('nak', ['--version'], {encoding: 'utf8', timeout: 5000});
  if (version.error || version.status !== 0 || version.stdout?.trim() !== 'nak version v0.21.2') {
    throw new BunkerError('Install the verified nak v0.21.2 before this remote-signing check.');
  }
  const content = `Distributed-bunker signing check only; not for publication. ${randomUUID()}`;
  const result = run('nak', ['event', '--kind', '1', '--content', content], {
    env: {...process.env, NOSTR_SECRET_KEY: connection.bunker_url},
    stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', timeout: 60000, maxBuffer: 1024 * 1024,
  });
  let event;
  try { event = JSON.parse(result.stdout); } catch { /* Never echo raw signer output. */ }
  if (result.error || result.status !== 0 || !validEvent(event) || event.pubkey !== receipt.pubkey ||
      event.kind !== 1 || event.content !== content || event.tags.length !== 0) {
    throw new BunkerError('Remote signing check failed; raw signer output suppressed. No article broadcast requested.');
  }
  return {npub: receipt.npub, event_id: event.id, signature_validation: 'passed',
    network_actions: 'NIP-46 signing exchange only; signed test note was not broadcast'};
}

export function argumentsFor(argv) {
  const command = argv[0] || 'help';
  if (!['help', 'preview', 'provision', 'status', 'sign-check'].includes(command)) throw new BunkerError('Unknown command.');
  const booleans = ['key-backed-up', 'accept-remote-signers', 'accept-coordinator-ack-only', 'resume-preflight', 'resume-unsent', 'query-relays'];
  const strings = ['key-file', 'expect-npub', 'config', 'state-dir', 'confirm-provision', 'confirm-remote-sign'];
  const options = {};
  for (let i = 1; i < argv.length; i++) {
    const name = argv[i].slice(2);
    if (!argv[i].startsWith('--') || Object.hasOwn(options, name)) throw new BunkerError('Invalid or duplicate option.');
    if (booleans.includes(name)) options[name] = true;
    else if (strings.includes(name) && argv[i + 1] && !argv[i + 1].startsWith('--')) options[name] = argv[++i];
    else throw new BunkerError('Unknown or missing option value.');
  }
  const allowed = {
    help: [], preview: ['key-file', 'expect-npub', 'config'],
    provision: ['key-file', 'expect-npub', 'config', 'state-dir', 'confirm-provision', 'key-backed-up', 'accept-remote-signers', 'accept-coordinator-ack-only', 'resume-preflight', 'resume-unsent'],
    status: ['state-dir', 'query-relays'], 'sign-check': ['state-dir', 'confirm-remote-sign'],
  }[command];
  if (Object.keys(options).some(name => !allowed.includes(name))) throw new BunkerError('Option not supported by this command.');
  return {command, options};
}

export async function main(argv) {
  const {command, options: o} = argumentsFor(argv);
  if (command === 'help') {
    console.log('Promenade distributed-bunker setup helper (Node 24+).\n' +
      'preview --key-file ABS --expect-npub NPUB [--config FILE]\n' +
      'provision --key-file ABS --expect-npub NPUB --state-dir ABS --confirm-provision NPUB --key-backed-up --accept-remote-signers --accept-coordinator-ack-only [--resume-preflight | --resume-unsent] [--config FILE]\n' +
      'status --state-dir ABS [--query-relays]\n' +
      'sign-check --state-dir ABS --confirm-remote-sign NPUB\n' +
      'Private files/state must be outside Git/build, mode 600/700. No command runs during builds.');
    return;
  }
  if (command === 'status' || command === 'sign-check') {
    if (!o['state-dir']) throw new BunkerError('--state-dir is required.');
    const result = command === 'status' ? await status(o['state-dir'], o['query-relays'])
      : signCheck(o['state-dir'], o['confirm-remote-sign']);
    console.log(JSON.stringify(result, null, 2));
    return;
  }
  if (!o['key-file'] || !o['expect-npub']) throw new BunkerError('--key-file and --expect-npub are required.');
  const key = readKey(o['key-file']);
  try {
    const config = validateConfig(JSON.parse(readFileSync(o.config || DEFAULT_CONFIG, 'utf8')));
    const plan = preview(key, config, o['expect-npub']);
    if (command === 'preview') console.log(JSON.stringify(plan, null, 2));
    else {
      if (!o['state-dir']) throw new BunkerError('--state-dir is required.');
      const result = await provision({key, config, expectedNpub: plan.npub, directory: o['state-dir'],
        confirm: o['confirm-provision'], keyBackedUp: o['key-backed-up'], acceptRemoteSigners: o['accept-remote-signers'],
        acceptCoordinatorAckOnly: o['accept-coordinator-ack-only'], resumePreflight: o['resume-preflight'],
        resumeUnsent: o['resume-unsent'],
        progress: item => console.error(JSON.stringify(item))});
      console.log(JSON.stringify(result, null, 2));
    }
  } finally { key.fill(0); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main(process.argv.slice(2)).catch(error => {
    console.error(safeErrorMessage(error));
    process.exitCode = 1;
  });
}
