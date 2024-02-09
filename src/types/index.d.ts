import {createClient, createCluster} from "redis";

export interface TelosEvmConfig {
    chainId: number;
    blockNumberDelta: number;
    antelopeChainId: string;
    debug: boolean;
    nodeName: string,
    apiHost: string;
    apiPort: number;
    nodeosRead: string,
    nodeosWrite: string,
    signerAccount: string;
    signerPermission: string;
    signerKey: string;
    retryTrxNumBlocks: number;
    contracts: {
        main: string;
    }
    indexerWebsocketHost: string;
    indexerWebsocketPort: number;
    indexerWebsocketUri: string;
    rpcWebsocketHost: string;
    rpcWebsocketPort: number;
    redisHost: string;
    redisPort: number;
    redisUser: string;
    redisPass: string;
    elasticNode: string;
    elasticUser: string;
    elasticPass: string;
    elasticIndexPrefix: string;
    elasticIndexVersion: string;
    orderNonces: boolean;
    orderNonceRetryTimeout: number;
    syncingThreshhold: number;
    acceptableLibLag: number;
    acceptableHeadLagMs: number;
}

/** A conventional Redis connection. */
export type RedisClientConnection = ReturnType<typeof createClient>

/** A clustered Redis connection. */
export type RedisClusterConnection = ReturnType<typeof createCluster>

/** A Redis connection, clustered or conventional. */
export type RedisConnection = RedisClientConnection | RedisClusterConnection