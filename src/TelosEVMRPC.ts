import {fastify, FastifyInstance, FastifyListenOptions} from "fastify";
import fastifyTraps from '@dnlup/fastify-traps'
import fastifyCors from '@fastify/cors'
import Common, {default as ethCommon, Hardfork} from '@ethereumjs/common';
import {createLogger} from "./util/logger";
import evmRoute from './routes/evm'
import {RedisClientConnection, TelosEvmConfig} from "./types";
import WebsocketRPC from "./ws/WebsocketRPC";
import {
    APIClient,
    FetchProvider,
    Name,
    PrivateKey,
} from '@wharfkit/antelope'
import {Client} from "@elastic/elasticsearch";
import { createClient } from 'redis'

import {RedisClientOptions} from "@redis/client";
import {ClientOptions} from "@elastic/elasticsearch/lib/client";
import {TelosEvmApi} from "./telosevm-js/telos";

const logger = createLogger(`telos-evm-rpc`)

export default class TelosEVMRPC {
    debug = false;

    common: Common;
    baseChain = 'mainnet';
    hardfork = Hardfork.London;
    fastify: FastifyInstance;
    config: TelosEvmConfig;
    websocketRPC: WebsocketRPC

    constructor(config: TelosEvmConfig) {
        this.config = config
        this.debug = config.debug
        if (config.chainId) {
            this.common = Common.forCustomChain(
                this.baseChain,
                {chainId: config.chainId},
                this.hardfork,
                ['istanbul', 'berlin', 'london']
            );
        }

        this.fastify = fastify({
            trustProxy: true,
            logger: this.debug ? logger : false
        })
    }

    async start() {
        await this.fastify.register(fastifyCors)
        this.fastify.register(fastifyTraps, {
            timeout: 3000
        })

        this.fastify.decorate('redis', await this.createRedisClient());
        this.fastify.decorate('elastic', this.createElasticsearchClient())
        logger.info('All services reached')
        await this.addRoutes();
        const opts: FastifyListenOptions = {
            host: this.config.apiHost,
            port: this.config.apiPort
        }

        this.fastify.listen(opts, err => {
            logger.info(`Starting teloscan-evm-rpc at ${opts.host}:${opts.port}`);

            if (err) {
                logger.error(`ERROR running teloscan-evm-rpc: ${JSON.stringify(err.message)}`);
                throw err;
            }
        })
    }

    async addRoutes(): Promise<void> {
        this.fastify.decorate('evm', new TelosEvmApi({
            // TODO: maybe this should be nodeos_write?  Need to check where we use fastify.evm and what it should be,
            //  possibly split up what we do so we have more granular control of which node type we use for which type of calls
            nodeosRead: this.config.nodeosRead,
            nodeosWrite: this.config.nodeosWrite,
            evmChainId: this.config.chainId,
            antelopeChainId: this.config.antelopeChainId,
            telosContract: this.config.contracts.main,
            telosPrivateKey: this.config.signerKey,
            retryTrxNumBlocks: this.config.retryTrxNumBlocks,
            signingPermission: this.config.signerPermission
        }));
        this.fastify.evm.setDebug(this.config.debug);

        this.fastify.decorate('rpcAccount', Name.from(this.config.signerAccount))
        this.fastify.decorate('rpcPermission', Name.from(this.config.signerPermission))
        this.fastify.decorate('rpcKey', PrivateKey.from(this.config.signerKey))
        this.fastify.decorate('readApi', new APIClient({provider: new FetchProvider(this.config.nodeosRead)}))

        this.fastify.decorate('rpcPayloadHandlerContainer', {});

        await evmRoute(this.fastify, this.config);

        this.websocketRPC = new WebsocketRPC(this.config, this.fastify.rpcPayloadHandlerContainer);
    }

    createElasticsearchClient(): Client {
        const clientOpts: ClientOptions = {
            node: this.config.elasticNode,
        }

        const user = this.config.elasticUser;
        const pass = this.config.elasticPass;

        if (user && pass) {
            clientOpts.auth = {
                username: this.config.elasticUser,
                password: this.config.elasticPass
            }
        }
        return new Client(clientOpts);
    }

    async createRedisClient(): Promise<RedisClientConnection> {
        const maxConnectRetry = 10
        const minConnectDelay = 100; // Milliseconds
        const maxConnectDelay = 60000; // Milliseconds

        const opts: RedisClientOptions = {
            url: `redis://${this.config.redisHost}:${this.config.redisPort}`,
            socket: {
                connectTimeout: 5000,
                reconnectStrategy: (retries) => {
                    if (retries > maxConnectRetry) {
                        console.log("Too many retries on redis. Connection Terminated");
                        return new Error("Redis reconnect strategy, too many retries.");
                    } else {
                        const wait = Math.min(minConnectDelay * Math.pow(2, retries), maxConnectDelay);
                        console.log("Redis reconnect strategy, waiting", wait, "milliseconds");
                        return wait;
                    }
                }
            }
        }
        if (this.config.redisUser && this.config.redisPass) {
            opts.username = this.config.redisUser
            opts.password = this.config.redisPass
        }
        const client = createClient(opts)
        client.on('error', err => console.error('Redis client error', err));
        client.on('connect', () => console.log('Redis client is connect'));
        client.on('reconnecting', () => console.log('Redis client is reconnecting'));
        client.on('ready', () => console.log('Redis client is ready'));
        await client.connect()

        return client
    }

}
