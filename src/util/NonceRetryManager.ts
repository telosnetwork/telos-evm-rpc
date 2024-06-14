import { FeeMarketEIP1559Transaction, LegacyTransaction } from "@ethereumjs/tx"
import {TelosEvmConfig} from "../types";
import {FastifyInstance} from "fastify";
import {addHexPrefix} from "@ethereumjs/util";
import * as ws from "ws";
import {TelosEvmApi} from "../telosevm-js/telos";

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
    private getInfo: Function;
    private queuedSenders: Map<string, FailedTrxList>;
    private retryTimeout: number;
    constructor(opts: TelosEvmConfig, telosJs: TelosEvmApi, fastify: FastifyInstance, makeTrxVars: Function, getInfo: Function) {
        this.telosEvmJs = telosJs;
        this.opts = opts;
        this.retryTimeout = opts.orderNonceRetryTimeout || 60000;
        this.fastify = fastify;
        this.makeTrxVars = makeTrxVars;
        this.getInfo = getInfo
        this.queuedSenders = new Map();
    }

    public async start() {
        this.pollPendingTransactions();
    }

    public submitFailedRawTrx(rawTx: string): string {
        if (rawTx && rawTx.startsWith('0x'))
            rawTx = rawTx.substring(2);

        let trx = (rawTx.startsWith('02')) ? 
            FeeMarketEIP1559Transaction.fromSerializedTx(Buffer.from(rawTx, 'hex'), {common: this.telosEvmJs.chainConfig}) :
            LegacyTransaction.fromSerializedTx(Buffer.from(rawTx, 'hex'), { common: this.telosEvmJs.chainConfig})
        ;

        const sender: string = trx.getSenderAddress().toString();
        const nonce: number = Number(trx.nonce);

        const failedTrx = {
            sender, nonce, rawTx,
            firstFailed: Date.now(),
            lastRetry: Date.now()
        }

        if (this.queuedSenders.has(sender))
            this.queuedSenders.get(sender).addFailedTrx(failedTrx);
        else
            this.queuedSenders.set(sender, new FailedTrxList(sender, failedTrx));

        return addHexPrefix(trx.hash().toString());
    }

    private async pollPendingTransactions() {
        while (true) {
            for (let [sender, failedTrxList] of this.queuedSenders) {
                try {
                    if (failedTrxList.size() === 0) {
                        this.queuedSenders.delete(sender);
                        continue;
                    }

                    // Get the lowest nonce and maybe retry it
                    let failedTrx = failedTrxList.getLowestNonce();

                    // if we hit the timeout, we should stop retrying this transaction and move onto the next sender for now
                    if ((Date.now() - failedTrx.firstFailed) > this.retryTimeout) {
                        failedTrxList.removeFailedTrx(failedTrx.nonce);
                        continue;
                    }

                    // If we're past the retry duration, let's retry it again
                    if ((Date.now() - failedTrx.lastRetry) > RETRY_INTERVAL) {
                        let noNonceFailure = await this.sendRawTrx(failedTrx);
                        while (noNonceFailure) {
                            failedTrxList.removeFailedTrx(failedTrx.nonce);
                            if (failedTrxList.size() === 0)
                                break;

                            failedTrx = failedTrxList.getLowestNonce();
                            noNonceFailure = await this.sendRawTrx(failedTrx);
                        }
                    }
                } catch (e) {
                    console.log(`Error in nonce retry loop: ${e.message}`);
                    console.error(e);
                }
            }
            await this.sleep(SLEEP_DURATION);
        }
    }

    private async sleep(ms: number) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    private async sendRawTrx(failedTx: FailedTrx): Promise<boolean> {
        try {
            failedTx.lastRetry = Date.now();
            const rawResponse = await this.telosEvmJs.raw({
                account: this.opts.signerAccount,
                tx: failedTx.rawTx,
                ram_payer: this.telosEvmJs.telosContract,
                trxVars: await this.makeTrxVars(),
                getInfoResponse: await this.getInfo()
            });
            return true;
        } catch (e) {
            const assertionMessage = e?.details[0]?.message
            return !(assertionMessage && assertionMessage.includes('incorrect nonce'));
        }
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