import TelosEVMRPC from './TelosEVMRPC'
import {TelosEvmConfig} from "./types";
import {EventEmitter} from 'events';

EventEmitter.defaultMaxListeners = 400;

const config: TelosEvmConfig = require("../config.json") as TelosEvmConfig;
const rpc: TelosEVMRPC = new TelosEVMRPC(config);

;(async () => {
    console.log("Starting Telos EVM RPC...");
    await rpc.start();
    console.log("Telos EVM RPC started!!!");
})()
