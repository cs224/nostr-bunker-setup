import {parentPort, workerData} from 'node:worker_threads';
import {minePow} from '@nostr/tools/nip13';

// No private key, network, or logging in the worker: only an unsigned encrypted envelope.
parentPort.postMessage(minePow(workerData.unsigned, workerData.difficulty));
