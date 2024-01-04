import {createClient, createCluster} from "redis";

export interface TelosEvmConfig {
    chainId: number;
    blockNumberDelta: number;
    antelopeChainId: string;
    debug: boolean;
    apiHost: string;
    apiPort: number;
    nodeos_read: string,
    nodeos_write: string,
    signer_account: string;
    signer_permission: string;
    signer_key: string;
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