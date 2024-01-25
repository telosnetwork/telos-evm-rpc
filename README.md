# Telos EVM RPC

Required plugin config at config.json

```json
{
  "chainId": 41,
  "pm2Name": "telos-testnet-rpc",
  "pm2Instances": 4,
  "debug": true,
  "apiHost": "127.0.0.1",
  "apiPort": 3000,
  "nodeosRead": "http://127.0.0.1:28888",
  "nodeosWrite": "http://127.0.0.1:28888",
  "signerAccount": "rpc.evm",
  "signerPermission": "rpc",
  "signerKey": "5...something",
  "contracts": {
    "main": "eosio.evm"
  },
  "indexerWebsocketHost": "0.0.0.0",
  "indexerWebsocketPort": "7800",
  "indexerWebsocketUri": "ws://127.0.0.1:7800/evm",
  "rpcWebsocketHost": "0.0.0.0",
  "rpcWebsocketPort": "7900",
  "redisHost": "127.0.0.1",
  "redisPort": 6379,
  "redisUser": "",
  "redisPass": "",
  "elasticNode": "http://127.0.0.1:9200",
  "elasticUser": "elastic",
  "elasticPass": "secretstuff",
  "elasticIndexPrefix": "telos-testnet",
  "elasticIndexVersion": "v1.5",
  "antelopeChainId": "1eaa0824707c8c16bd25145493bf062aecddfeb56c736f6ba6397f3195f33c9f"
}

```
### Implemented Routes

#### /evm (JSON RPC 2.0)

Methods:
  - eth_accounts
  - eth_blockNumber
  - eth_call
  - eth_chainId
  - eth_estimateGas
  - eth_getBalance
  - eth_getBlockByNumber
  - eth_getBlockByHash
  - eth_getBlockTransactionCountByNumber
  - eth_getBlockTransactionCountByHash
  - eth_getCode
  - eth_getLogs
  - eth_getStorageAt
  - eth_getTransactionCount
  - eth_getTransactionByHash
  - eth_getTransactionReceipt
  - eth_getUncleCountByBlockNumber
  - eth_getUncleCountByBlockHash
  - eth_gasPrice
  - eth_sendTransaction
  - eth_sendRawTransaction
  - net_listening
  - net_version
