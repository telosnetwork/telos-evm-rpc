import TelosEVMRPC from './TelosEVMRPC'
import {TelosEvmConfig} from "./types";
import {EventEmitter} from 'events';
import {Command} from 'commander';
import {readFileSync} from 'fs';

EventEmitter.defaultMaxListeners = 400;

const program = new Command();

program
    .option('-c, --config [path to config.json]', 'Path to config.json file', 'config.json')
    .action(async (options) => {
        const config: TelosEvmConfig = JSON.parse(readFileSync(options.config).toString());
        const rpc: TelosEVMRPC = new TelosEVMRPC(config);

        console.log("Starting Telos EVM RPC...");
        await rpc.start();
        console.log("Telos EVM RPC started!!!");
    });

program.parse(process.argv);