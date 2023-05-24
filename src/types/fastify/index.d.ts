import {JsonRpc} from "eosjs";
import {APIClient, Name, PrivateKey} from "@wharfkit/antelope";
import {RedisClientType} from "redis";
import {Client} from "@elastic/elasticsearch";

declare module 'fastify' {
    export interface FastifyInstance {
        evm: any;
        rpcPayloadHandlerContainer: any;
        cachingApi: any;
        eosjsRpc: JsonRpc;
        readApi: APIClient;
        rpcAccount: Name;
        rpcPermission: Name;
        rpcKey: PrivateKey;
        redis: RedisClientType;
        elastic: Client
    }
}
