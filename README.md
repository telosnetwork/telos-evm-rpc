# Telos EVM RPC

Required plugin config at config.json

```json
{
  "chainId": 40,
  "pm2Name": "mainnet15-rpc",
  "pm2Instances": 2,
  "debug": false,
  "apiHost": "127.0.0.1",
  "apiPort": 7000,
  "nodeosRead": "http://127.0.0.1:8888",
  "nodeosWrite": "http://127.0.0.1:8888",
  "signerAccount": "rpc.evm",
  "signerPermission": "rpc",
  "signerKey": "5Kj.....................",
  "contracts": {
    "main": "eosio.evm"
  },
  "indexerWebsocketHost": "127.0.0.1",
  "indexerWebsocketPort": "7300",
  "indexerWebsocketUri": "ws://127.0.0.1:7300/evm",
  "rpcWebsocketHost": "127.0.0.1",
  "rpcWebsocketPort": "7400",
  "redisHost": "127.0.0.1",
  "redisPort": 6379,
  "redisUser": "",
  "redisPass": "",
  "elasticNode": "http://127.0.0.1:9200",
  "elasticUser": "elastic",
  "elasticPass": "secretstuff",
  "elasticIndexPrefix": "telos-mainnet",
  "elasticIndexVersion": "15",
  "antelopeChainId": "4667b205c6838ef70ff7988f6e8257e8be0e1284a2f59699054a018f743b1d11",
  "blockNumberDelta": 36
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
  - eth_getTransactionByBlockHashAndIndex
  - eth_getTransactionReceipt
  - eth_getUncleCountByBlockNumber
  - eth_getUncleCountByBlockHash
  - eth_gasPrice
  - eth_sendTransaction
  - eth_sendRawTransaction
  - net_listening
  - net_version
