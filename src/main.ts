import TelosEVMRPC from './TelosEVMRPC'
import {TelosEvmConfig} from "./types";

const config: TelosEvmConfig = require("../config.json") as TelosEvmConfig;
const rpc: TelosEVMRPC = new TelosEVMRPC(config);

;(async () => {
    console.log("Starting Telos EVM RPC...");
    await rpc.start();
    console.log("Telos EVM RPC started!!!");
})()
