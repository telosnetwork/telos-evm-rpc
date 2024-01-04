import {APIClient, Name, PrivateKey} from "@wharfkit/antelope";
import {RedisClientType} from "redis";
import {Client} from "@elastic/elasticsearch";
import {TelosEvmApi} from "../../telosevm-js/telos";

declare module 'fastify' {
    export interface FastifyInstance {
        evm: TelosEvmApi;
        rpcPayloadHandlerContainer: any;
        cachingApi: any;
        readApi: APIClient;
        rpcAccount: Name;
        rpcPermission: Name;
        rpcKey: PrivateKey;
        redis: RedisClientType;
        elastic: Client
    }
}
