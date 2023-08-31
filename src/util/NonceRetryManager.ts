import { Transaction } from "@ethereumjs/tx"
import {TelosEvmApi} from "@telosnetwork/telosevm-js";
import {TelosEvmConfig} from "../types";
import {FastifyInstance} from "fastify";

interface FailedTrx {
    sender: string;
    nonce: number;
    rawTx: string;
    firstFailed: number;
    lastRetry: number;
}

const SLEEP_DURATION = 200;
const RETRY_INTERVAL = 200;

export default class NonceRetryManager {
    private telosEvmJs: TelosEvmApi;
    private opts: TelosEvmConfig;
    private fastify: FastifyInstance;
    private makeTrxVars: Function;
    private queuedSenders: Map<string, FailedTrxList>;
    private retryTimeout: number;
    constructor(opts: TelosEvmConfig, telosJs: TelosEvmApi, fastify: FastifyInstance, makeTrxVars: Function) {
        this.telosEvmJs = telosJs;
        this.opts = opts;
        this.retryTimeout = opts.orderNonceRetryTimeout || 2000;
        this.fastify = fastify;
        this.makeTrxVars = makeTrxVars;
        this.queuedSenders = new Map();
    }

    public async start() {
        this.pollPendingTransactions();
    }

    public submitFailedRawTrx(rawTx: string): string {
        let trx = Transaction.fromSerializedTx(Buffer.from(rawTx, 'hex'), {
            common: this.telosEvmJs.chainConfig
        });

        const sender = trx.getSenderAddress().toString();
        const nonce = trx.nonce.toNumber();

        const failedTrx = {
            sender, nonce, rawTx,
            firstFailed: Date.now(),
            lastRetry: Date.now()
        }

        if (this.queuedSenders.has(sender))
            this.queuedSenders.get(sender).addFailedTrx(failedTrx);
        else
            this.queuedSenders.set(sender, new FailedTrxList(sender, failedTrx));

        return trx.hash().toString('hex');
    }

    private async pollPendingTransactions() {
        while (true) {
            for (let sender in this.queuedSenders) {
                const failedTrxList = this.queuedSenders.get(sender);
                if (failedTrxList.size() === 0) {
                    this.queuedSenders.delete(sender);
                    continue;
                }

                // Get the lowest nonce and maybe retry it
                const failedTrx = failedTrxList.getLowestNonce();

                // if we hit the timeout, we should stop retrying this transaction and move onto the next sender for now
                if ((Date.now() - failedTrx.firstFailed) > this.retryTimeout) {
                    failedTrxList.removeFailedTrx(failedTrx.nonce);
                    continue;
                }

                // If we're past the retry duration, let's retry it again
                if ((Date.now() - failedTrx.lastRetry) > RETRY_INTERVAL) {
                    const success = await this.sendRawTrx(failedTrx.rawTx);
                    if (success)
                        failedTrxList.removeFailedTrx(failedTrx.nonce);
                }
            }
            await this.sleep(SLEEP_DURATION);
        }
    }

    private async sleep(ms: number) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async sendRawTrx(signedTx: string): Promise<boolean> {
        const rawResponse = await this.telosEvmJs.telos.raw({
            account: this.opts.signer_account,
            tx: signedTx,
            ram_payer: this.telosEvmJs.telos.telosContract,
            api: this.fastify.cachingApi,
            trxVars: await this.makeTrxVars()
        });

        let consoleOutput = rawResponse.telos.processed.action_traces[0].console;

        return !consoleOutput.includes('incorrect nonce');
    }

}

class FailedTrxList {
    private sender: string;
    private failedTrxs: FailedTrx[];

    constructor(sender: string, initialFailedTrx: FailedTrx) {
        this.sender = sender;
        this.failedTrxs = [initialFailedTrx];
    }

    public removeFailedTrx(nonce: number) {
        this.failedTrxs = this.failedTrxs.filter(failedTrx => failedTrx.nonce !== nonce);
    }

    public size(): number {
        return this.failedTrxs.length;
    }
    public getLowestNonce(): FailedTrx {
        return this.failedTrxs.length > 0 ? this.failedTrxs[0] : null;
    }

    public addFailedTrx(failedTrx: FailedTrx) {
        for (let i = 0; i < this.failedTrxs.length; i++) {
            const thisTrx = this.failedTrxs[i];
            if (thisTrx.nonce == failedTrx.nonce) {
                // if we already had a failed trx for this nonce, replace the old one and return
                this.failedTrxs[i] = failedTrx;
                return;
            }

            // if the failed trx nonce is bigger than the current one in the array, we can safely assume the array is
            //    sorted asc by nonce so we don't need to look any further because we'd have seen it already
            if (failedTrx.nonce > thisTrx.nonce)
                break;
        }

        // we didn't have this one yet, add it and re-sort our list
        this.failedTrxs.push(failedTrx);
        this.sort();
    }

    private sort() {
        // TODO: quicksort?
        this.failedTrxs = this.failedTrxs.sort((a: FailedTrx, b: FailedTrx): number => {
            return a.nonce - b.nonce;
        })
    }
}