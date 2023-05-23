import {fastify, FastifyInstance, FastifyListenOptions} from "fastify";
import fastifyTraps from '@dnlup/fastify-traps'
import fastifyCors from '@fastify/cors'
import fetch from "node-fetch";
import {join} from "path";
import {Transaction} from '@ethereumjs/tx';
import Common, {default as ethCommon} from '@ethereumjs/common';
import Bloom from "./bloom";
import {blockHexToHash, toChecksumAddress} from "./util/utils"
import {createLogger} from "./util/logger";
import evmRoute from './routes/evm'
import RPCBroadcaster from "./ws/RPCBroadcaster";
import {RedisClientConnection, TelosEvmConfig} from "./types";
import WebsocketRPC from "./ws/WebsocketRPC";
import { Api, JsonRpc, RpcError } from 'eosjs';
import {
    Action,
    APIClient,
    FetchProvider,
    Name,
    PrivateKey,
    SignedTransaction,
    Struct,
    Transaction as AntelopeTransaction,
} from '@greymass/eosio'
import {Client, ClientOptions} from "@elastic/elasticsearch";
import type { RedisClientType } from 'redis'
import { createClient } from 'redis'

import {RedisClientOptions} from "@redis/client";

const logger = createLogger(`telos-evm-rpc`)
const BN = require('bn.js');
const createKeccakHash = require('keccak');
const {TelosEvmApi} = require('@telosnetwork/telosevm-js');

const KEYWORD_STRING_TRIM_SIZE = 32000;
const RECEIPT_LOG_START = "RCPT{{";
const RECEIPT_LOG_END = "}}RCPT";

export default class TelosEVMRPC {
    debug = false;

    common: Common;
    decimalsBN = new BN('1000000000000000000');
    baseChain = 'mainnet';
    hardfork = 'istanbul';
    counter = 0;
    fastify: FastifyInstance;
    config: TelosEvmConfig;
    rpcBroadcaster: RPCBroadcaster;
    websocketRPC: WebsocketRPC

    constructor(config: TelosEvmConfig) {
        this.config = config
        this.debug = config.debug
        if (config.chainId) {
            this.common = ethCommon.forCustomChain(
                this.baseChain,
                {chainId: config.chainId},
                this.hardfork
            );
            //this.registerStreamHandlers();
        }

        this.fastify = fastify({
            trustProxy: true,
            logger
        })
    }

    /*
        this.streamHandlers.push({
            event: 'trace',
            handler: async streamEvent => {
                try {
                    const headers = streamEvent.properties.headers;
                    if (headers) {
                        if (headers.event === 'delta' && headers.code === 'eosio' && headers.table === 'global') {
                            if (streamEvent.content) {
                                const evPayload = {
                                    event: 'evm_block',
                                    globalDelta: streamEvent.content.toString()
                                };
                                process.send(evPayload);
                            }
                        } else if (headers.event === 'trace' && headers.account === 'eosio.evm' && headers.name === 'raw') {
                            if (streamEvent.content) {
                                const evPayload = {
                                    event: 'evm_transaction',
                                    actionTrace: streamEvent.content.toString()

                                };
                                process.send(evPayload);
                            }
                        }
                    }
                } catch (e) {
                    console.log(`Error during stream handler: ${e.message}`)
                }
            }
        });
    }

    initHandlerMap(): any {
        return {
            'evm_transaction': (msg) => this.rpcBroadcaster.broadcastRaw(msg.actionTrace),
            'evm_block': (msg) => this.rpcBroadcaster.handleGlobalDelta(msg.globalDelta)
        };
    }
     */

    async start() {
        await this.fastify.register(fastifyCors)
        this.fastify.register(fastifyTraps, {
            timeout: 3000
        })

        this.fastify.decorate('eosjsRpc', new JsonRpc(this.config.nodeos_read))
        this.fastify.decorate('redis', await this.createRedisClient())
        this.fastify.decorate('elastic', this.createElasticsearchClient())
        await this.addRoutes();
        const opts: FastifyListenOptions = {
            host: this.config.apiHost,
            port: this.config.apiPort
        }

        this.fastify.listen(opts, err => {
            if (err) throw err
        })
    }

    async addRoutes(): Promise<void> {
        this.fastify.decorate('evm', new TelosEvmApi({
            // TODO: maybe this should be nodeos_write?  Need to check where we use fastify.evm and what it should be,
            //  possibly split up what we do so we have more granular control of which node type we use for which type of calls
            endpoint: this.config.nodeos_read,
            chainId: this.config.chainId,
            ethPrivateKeys: [],
            fetch: fetch,
            telosContract: this.config.contracts.main,
            telosPrivateKeys: [this.config.signer_key],
            signingPermission: this.config.signer_permission
        }));
        this.fastify.evm.setDebug(this.config.debug);

        this.fastify.decorate('rpcAccount', Name.from(this.config.signer_account))
        this.fastify.decorate('rpcPermission', Name.from(this.config.signer_permission))
        this.fastify.decorate('rpcKey', PrivateKey.from(this.config.signer_key))
        this.fastify.decorate('readApi', new APIClient({provider: new FetchProvider(this.config.nodeos_read)}))

        this.fastify.decorate('rpcPayloadHandlerContainer', {});

        await evmRoute(this.fastify, this.config);

        this.websocketRPC = new WebsocketRPC(this.config, this.fastify.rpcPayloadHandlerContainer);
    }

    createElasticsearchClient(): Client {
        return new Client({
            node: this.config.elasticNode,
            auth: {
                username: this.config.elasticUser,
                password: this.config.elasticPass
            }
        });
    }

    async createRedisClient(): Promise<RedisClientConnection> {
        const opts: RedisClientOptions = {
            url: `redis://${this.config.redisHost}:${this.config.redisPort}`
        }
        if (this.config.redisUser && this.config.redisPass) {
            opts.username = this.config.redisUser
            opts.password = this.config.redisPass
        }
        const client = createClient(opts)
        await client.connect()

        return client
    }

    logDebug(msg: String): void {
        if (this.debug) {
            console.log(msg);
        }
    }
}
