import {FastifyInstance, FastifyReply, FastifyRequest} from "fastify";
import {TelosEvmConfig} from "../../types";
import Bloom from "../../bloom";
import {
	toChecksumAddress,
	numToHex,
	removeZeroHexFromFilter,
	buildLogsObject,
	logFilterMatch,
	makeLogObject,
	BLOCK_TEMPLATE,
	GENESIS_BLOCKS,
	BLOCK_GAS_LIMIT,
	NULL_TRIE, EMPTY_LOGS, removeLeftZeros, leftPadZerosEvenBytes, toLowerCaseAddress, isHexPrefixed,
	parsePanicReason, parseRevertReason, toOpname

} from "../../util/utils"
import MyLogger from "../../logging";
import moment from "moment";
import {ethers, BigNumber} from 'ethers';
import { addHexPrefix } from '@ethereumjs/util';
import {
	API,
	Name,
	PrivateKey,
	SignedTransaction,
	Struct,
	Transaction, Bytes, Checksum160
} from '@wharfkit/antelope'
import NonceRetryManager from "../../util/NonceRetryManager";
import {TransactionVars} from "../../telosevm-js/telos";
import {estypes} from "@elastic/elasticsearch";

const BN = require('bn.js');
const GAS_PRICE_OVERESTIMATE = 1.00

const RECEIPT_LOG_START = "RCPT{{";
const RECEIPT_LOG_END = "}}RCPT";

const REVERT_FUNCTION_SELECTOR = '0x08c379a0'
const REVERT_PANIC_SELECTOR = '0x4e487b71'

const EOSIO_ASSERTION_PREFIX = 'assertion failure with message: '

@Struct.type('call')
export class Call extends Struct {
	@Struct.field(Name) ram_payer!: Name
	@Struct.field(Bytes) tx!: Bytes
	@Struct.field(Checksum160, {optional: true}) sender?: Checksum160
}

class Refund extends Struct {
	static abiName = 'call'
	static abiFields = [
		{
			name: 'ram_payer',
			type: Name,
		},
		{
			name: 'tx',
			type: Bytes,
		},
		{
			name: 'sender',
			type: Checksum160,
		}
	]
}

function jsonRPC2Error(reply: FastifyReply, type: string, requestId: string, message: string, code?: number) {
	let errorCode = code;
	switch (type) {
		case "InvalidRequest": {
			if (reply)
				reply.statusCode = 200;
			errorCode = -32600;
			break;
		}
		case "MethodNotFound": {
			if (reply)
				reply.statusCode = 200;
			errorCode = -32601;
			break;
		}
		case "ParseError": {
			if (reply)
				reply.statusCode = 400;
			errorCode = -32700;
			break;
		}
		case "InvalidParams": {
			if (reply)
				reply.statusCode = 400;
			errorCode = -32602;
			break;
		}
		case "InternalError": {
			if (reply)
				reply.statusCode = 500;
			errorCode = -32603;
			break;
		}
		default: {
			if (reply)
				reply.statusCode = 500;
			errorCode = -32603;
		}
	}
	let errorResponse = {
		jsonrpc: "2.0",
		id: requestId,
		error: {
			code: errorCode,
			message
		}
	};
	return errorResponse;
}

class TransactionError extends Error {
	public errorMessage: string
	public data: any
	public code: number
}

export default async function (fastify: FastifyInstance, opts: TelosEvmConfig) {

	const methods: Map<string, (params?: any) => Promise<any> | any> = new Map();
	const decimalsBN = new BN('1000000000000000000');
	const zeros = "0x0000000000000000000000000000000000000000";
	const chainAddr = [
		"0xb1f8e55c7f64d203c1400b9d8555d050f94adf39",
		"0x9f510b19f1ad66f0dcf6e45559fab0d6752c1db7",
		"0xb8e671734ce5c8d7dfbbea5574fa4cf39f7a54a4",
		"0xb1d3fbb2f83aecd196f474c16ca5d9cffa0d0ffc",
	];
	const chainIds = [1, 3, 4, 42];
	const METAMASK_EXTENSION_ORIGIN = 'chrome-extension://nkbihfbeogaeaoehlefnkodbefgpgknn';
	const GAS_OVER_ESTIMATE_MULTIPLIER = 1.25;

	const CHAIN_ID = opts.chainId.toString();
	const CHAIN_ID_HEX = addHexPrefix(opts.chainId.toString(16));
	const CACHE_PREFIX = opts.elasticIndexPrefix;
	const GENESIS_BLOCK = GENESIS_BLOCKS[CHAIN_ID_HEX];
	const GENESIS_BLOCK_HASH = GENESIS_BLOCK.hash;

	let Logger = new MyLogger(opts.debug);

	let nonceRetryManager = new NonceRetryManager(opts, fastify.evm, fastify, makeTrxVars, getInfo);
	nonceRetryManager.start();

	// 0 is healthy, 1 is lib lag, 2 is head lag
	let healthStatus = 0

	setInterval(async () => {
		// health check
		const getInfoResponse = await getInfo()
		const libBehind = getInfoResponse.head_block_num.value.sub(getInfoResponse.last_irreversible_block_num.value).gt(new BN(opts.acceptableLibLag))
		if (libBehind) {
			healthStatus = 1
			return
		}

		const headDelta = Date.now() - getInfoResponse.head_block_time.toMilliseconds()
		const headBehind = headDelta > opts.acceptableHeadLagMs
		if (headBehind) {
			healthStatus = 2
			return
		}

		healthStatus = 0

	}, 1000)

    // AUX FUNCTIONS

    async function getInfo(): Promise<API.v1.GetInfoResponse> {
		const key = `${CACHE_PREFIX}_get_info`
		const cachedData = await fastify.redis.get(key)
        if (cachedData) {
			return API.v1.GetInfoResponse.from(JSON.parse(cachedData));
        } else {
            //const apiResponse = await fastify.eosjs.rpc.get_info();
			const apiResponse: API.v1.GetInfoResponse = await fastify.readApi.v1.chain.get_info();
            await fastify.redis.set(key, JSON.stringify(apiResponse), {
				PX: 1000,
				NX: true
			});
            return apiResponse;
        }
    }

    async function makeTrxVars(): Promise<TransactionVars> {
        const getInfoResponse = await getInfo()
		const header = getInfoResponse.getTransactionHeader(45);
		return {
			expiration: header.expiration.toString(),
			ref_block_num: header.ref_block_num.toNumber(),
			ref_block_prefix: header.ref_block_prefix.toNumber()
		}
    }

	async function getVRS(receiptDoc): Promise<any> {
		let receipt = receiptDoc["@raw"];
		const v = removeLeftZeros(typeof receipt.v === 'string' ? receipt.v : receipt.v.toString(16), true);
		const r = removeLeftZeros(receipt.r, true);
		const s = removeLeftZeros(receipt.s, true);

		return {v,r,s};
	}

	async function searchActionByHash(trxHash: string, client: any): Promise<any> {
		Logger.debug(`searching action by hash: ${trxHash}`)
		try {
			let _hash = trxHash.toLowerCase();
			if (isHexPrefixed(_hash)) {
				_hash = _hash.slice(2);
			}
			const results = await fastify.elastic.search({
				index: `${opts.elasticIndexPrefix}-action-${opts.elasticIndexVersion}-*`,
				size: 1,
				query: {
					bool: {
						must: [{ term: { "@raw.hash": "0x" + _hash } }]
					}
				}
			});
			if(results?.hits?.hits?.length === 0){
				Logger.debug(`searching action by hash: ${trxHash} got no results`)
				return null;
			}
			// Logger.debug(`searching action by hash: ${trxHash} got result: \n${JSON.stringify(results?.hits)}`)
			return results?.hits?.hits[0]?._source;
		} catch (e) {
			Logger.error(client.ip + ' ' + JSON.stringify(e));
			return null;
		}
	}

	/*
	async function searchDeltasByHash(trxHash: string): Promise<any> {
		try {
			let _hash = trxHash.toLowerCase();
			if (isHexPrefixed(_hash)) {
				_hash = _hash.slice(2);
			}
			const results = await fastify.elastic.search({
				index: `${opts.elasticIndexPrefix}-delta-${opts.elasticIndexVersion}-*`,
				body: {
					size: 1,
					query: {
						bool: {
							must: [{ term: { "@receipt.hash": _hash } }]
						}
					}
				}
			});
			return results?.body?.hits?.hits[0]?._source;
		} catch (e) {
			Logger.error(e);
			return null;
		}
	}
	*/

	// borrowed from translator

	function indexToSuffixNum(index: string) {
		const spltIndex = index.split('-');
		const suffix = spltIndex[spltIndex.length - 1];
		return parseInt(suffix);
	}

	// TODO: do caching of delta indices?
	async function getOrderedDeltaIndices() {

		const deltaIndices: estypes.CatIndicesResponse = await fastify.elastic.cat.indices({
			index: `${opts.elasticIndexPrefix}-delta-*`,
			format: 'json'
		});
		deltaIndices.sort((a, b) => {
			const aNum = indexToSuffixNum(a.index);
			const bNum = indexToSuffixNum(b.index);
			if (aNum < bNum)
				return -1;
			if (aNum > bNum)
				return 1;
			return 0;
		});

		return deltaIndices;
	}

	function adjustBlockNum(num: number): number {
		// convert to native block num and divide over index size 10 million
		return Math.floor((num + opts.blockNumberDelta) / 1e7);
	}

	function indexSuffixForBlock(blockNumber: number): string {
		const adjustedNum = adjustBlockNum(blockNumber);
		return String(adjustedNum).padStart(8, '0');
	}

    async function getDeltaDocFromNumber(blockNumber: number) {
        const indexSuffix = indexSuffixForBlock(blockNumber);
		const results = await fastify.elastic.search({
			index: `${opts.elasticIndexPrefix}-delta-${opts.elasticIndexVersion}-${indexSuffix}`,
			size: 1,
			query: {
				bool: {
					must: [{ term: { "@global.block_num": blockNumber } }]
				}
			}
		});
		const blockDelta = results?.hits?.hits[0]?._source;
		return blockDelta;
	}

    async function emptyBlockFromDelta(blockDelta: any) {
		const blockNumberHex = addHexPrefix(blockDelta['@global'].block_num.toString(16));
		const timestamp = new Date(blockDelta['@timestamp']).getTime() / 1000;
        const parentHash = addHexPrefix(blockDelta['@evmPrevBlockHash']);
		const blockHash = addHexPrefix(blockDelta["@evmBlockHash"]);
		const extraData = addHexPrefix(blockDelta['@blockHash']);

		return Object.assign({}, BLOCK_TEMPLATE, {
			gasUsed: "0x0",
			parentHash: parentHash,
			hash: blockHash,
			logsBloom: addHexPrefix(new Bloom().bitvector.toString("hex")),
			number: blockNumberHex,
			timestamp: removeLeftZeros(timestamp?.toString(16)),
			transactions: [],
			extraData: extraData
		});
	}

	async function emptyBlockFromNumber(blockNumber: number) {
		try {
			const blockDelta = await getDeltaDocFromNumber(blockNumber);
			if (!blockDelta)
				return null;

			return await emptyBlockFromDelta(blockDelta);
		} catch (e) {
			Logger.error(e);
			return null;
		}
	}

	async function emptyBlockFromHash(blockHash: string) {
		try {
			const results = await fastify.elastic.search({
				index: `${opts.elasticIndexPrefix}-delta-${opts.elasticIndexVersion}-*`,
				size: 1,
				query: {
					bool: {
						must: [{term: {"@evmBlockHash": blockHash}}]
					}
				}
			});
			let blockDelta = results?.hits?.hits[0]?._source;
			if (!blockDelta) {
				return null;
			}

			return await emptyBlockFromDelta(blockDelta);
		} catch (e) {
			Logger.error(e);
			return null;
		}
	}


	async function reconstructBlockFromReceipts(receipts: any[], full: boolean, client: any) {
		try {
			let blockHash;
			let blockHex: string;
			let blockNum: number;
			let logsBloom: any = null;
			let bloom = new Bloom();
			const trxs = [];
			//Logger.debug(`Reconstructing block from receipts: ${JSON.stringify(receipts)}`)
			for (const receiptDoc of receipts) {
				const {v, r, s} = await getVRS(receiptDoc._source);
				const receipt = receiptDoc._source['@raw'];

				if (!blockHash) {
					blockHash = addHexPrefix(receipt['block_hash']);
				}
				if (!blockHex) {
					blockNum = Number(receipt['block']);
					blockHex = addHexPrefix(blockNum.toString(16));
				}
				if (receipt['logsBloom']){
					bloom.or(new Bloom(Buffer.from(receipt['logsBloom'], "hex")));
				}
				let finalFrom = receipt['from'];
				if (receipt['from'] == zeros)
					finalFrom = toChecksumAddress(receipt['from']);
				if (!full) {
					trxs.push(receipt['hash']);
				} else {
					const hexBlockNum = removeLeftZeros(blockHex);
					const hexGas = removeLeftZeros(numToHex(receipt['gas_limit']));
					const hexGasPrice = removeLeftZeros(numToHex(receipt['charged_gas_price']));
					const hexNonce = removeLeftZeros(numToHex(receipt['nonce']));
					const hexTransactionIndex = removeLeftZeros(numToHex(receipt['trx_index']));
					const hexValue = addHexPrefix(receipt['value']);
					trxs.push({
						blockHash: blockHash,
						blockNumber: hexBlockNum,
						from: finalFrom,
						gas: hexGas,
						gasPrice: hexGasPrice,
						hash: receipt['hash'],
						input: receipt['input_data'],
						nonce: hexNonce,
						to: toChecksumAddress(receipt['to']),
						transactionIndex: hexTransactionIndex,
						value: hexValue,
						v, r, s
					});
				}
			}

			const block = await getDeltaDocFromNumber(blockNum);
			const timestamp = new Date(block['@timestamp']).getTime() / 1000;
			const gasUsedBlock = addHexPrefix(removeLeftZeros(new BN(block['gasUsed']).toString('hex')));
			const extraData = addHexPrefix(block['@blockHash']);
			const blockSize = addHexPrefix(block['size'].toString(16));
			const parentHash = addHexPrefix(block['@evmPrevBlockHash']);

			logsBloom = addHexPrefix(bloom.bitvector.toString("hex"));

			return Object.assign({}, BLOCK_TEMPLATE, {
				gasUsed: gasUsedBlock,
				gasLimit: BLOCK_GAS_LIMIT,
				parentHash: parentHash,
				hash: blockHash,
				logsBloom: logsBloom,
				number: removeLeftZeros(blockHex),
				timestamp: removeLeftZeros(timestamp?.toString(16)),
				transactions: trxs,
				size: blockSize,
				extraData: extraData,

				receiptsRoot: addHexPrefix(block['@receiptsRootHash']),
				transactionsRoot: addHexPrefix(block['@transactionsRoot'])
			});
		} catch (e) {
			Logger.error(client.ip + JSON.stringify(e));
			return null;
		}
	}

	async function getReceiptsByTerm(term: string, value: any) {
		const termStruct = {};
		termStruct[term] = value;
		const results = await fastify.elastic.search({
			index: `${opts.elasticIndexPrefix}-action-${opts.elasticIndexVersion}-*`,
			size: 2000,
			query: { bool: { must: [{ term: termStruct }] } }
		});
		return results?.hits?.hits;
	}

	async function getCurrentBlockNumber(indexed: boolean = false) {
		if (!indexed) {
			const key = `${CACHE_PREFIX}_last_onchain_block`;
			const cachedData = await fastify.redis.get(key);

			if (cachedData) {
				return cachedData;
			}

			const global = await fastify.readApi.v1.chain.get_table_rows({
				code: "eosio",
				scope: "eosio",
				table: "global",
				json: true
			});
			const blockNum = parseInt(global.rows[0].block_num, 10);
			const lastOnchainBlock = addHexPrefix(blockNum.toString(16));
			await fastify.redis.set(key, lastOnchainBlock, {
				PX: 500
			})
			return lastOnchainBlock;
		} else {
			const key = `${CACHE_PREFIX}_last_indexed_block`;
			const cachedData = await fastify.redis.get(key);

			if (cachedData && !cachedData.endsWith("NaN")){
				return cachedData;
			}

			const indices = (await getOrderedDeltaIndices()).reverse();

			let lastBlockNum: number;
			for (const index of indices) {
				const docsCount = parseInt(index['docs.count']);
				if (docsCount > 0) {
					const adjustedNum = indexToSuffixNum(index.index);
					lastBlockNum = (adjustedNum * 1e7) + docsCount - opts.blockNumberDelta - 1;
					break;
				}
			}

			let currentBlockNumber = addHexPrefix((Number(lastBlockNum)).toString(16));
			if (currentBlockNumber) {
				fastify.redis.set(key, currentBlockNumber, {
					PX: 500
				});
			}
			return currentBlockNumber;
		}
	}

	function makeInitialTrace(receipt, adHoc) {
		let gas = addHexPrefix((receipt['gasused'] as number).toString(16));
		let subtraces = 0;
		for(let i = 0; i < receipt.itxs.length; i++){
			if(receipt.itxs[i].traceAddress.length === 1){
				subtraces++;
			}
		}
		let trace: any = {
			action: {
				callType: 'call',
				from: toChecksumAddress(receipt['from']).toLowerCase(),
				gas: gas,
				input: receipt.input_data,
				value: removeLeftZeros(receipt.value)
			},
			result: {
				gasUsed: gas,
				output: addHexPrefix(receipt.output),
			},
			subtraces: subtraces,
			traceAddress: [],
			type: 'call'
		}

		if (receipt['to'])
			trace.action.to = toLowerCaseAddress(receipt['to']);

		// Todo: hope traceAddress matches the right trace and move that to makeTrace
		if (receipt?.errors?.length > 0)
			trace.error = receipt.errors[0];

		if (!adHoc) {
			trace.blockHash = addHexPrefix(receipt['block_hash']);
			trace.blockNumber = receipt['block'];
			trace.transactionHash = receipt['hash'];
			trace.transactionPosition = receipt['trx_index'];
		}

		return trace;
	}

	// https://openethereum.github.io/JSONRPC-trace-module
	// adHoc is for the Ad-hoc Tracing methods which have a slightly different trace structure than the
	//   Transaction-Trace Filtering (!adHoc) methods
	function makeTrace(receipt, itx, adHoc) {
		let trace: any = {
			action: {
				callType: toOpname(itx.callType),
				// why is 0x not in the receipt table?
				// use toChecksum to add it if not present and then lowercase it
				from: toChecksumAddress(itx.from).toLowerCase(),
				gas: addHexPrefix(itx.gas),
				input: addHexPrefix(itx.input),
				value: removeLeftZeros(itx.value)
			},
			result: {
				gasUsed: addHexPrefix(itx.gasUsed),
			},
			subtraces: parseInt(itx.subtraces),
			traceAddress: itx.traceAddress,
			type: itx.type
		}

		if(itx.init?.length > 0)
			trace.action.init = addHexPrefix(itx.init);

		if(itx.address)
			trace.result.address = addHexPrefix(itx.address);

		if(itx.code && itx.code !== "0")
			trace.result.code = addHexPrefix(itx.code);
		else if(itx.output)
			trace.result.output = addHexPrefix(itx.output);

		if(itx.error?.length > 0)
			trace.error = itx.error;

		if (itx.to)
			trace.action.to = toLowerCaseAddress(itx.to);

		if (!adHoc) {
			trace.blockHash = addHexPrefix(receipt['block_hash']);
			trace.blockNumber = receipt['block'];
			trace.transactionHash = receipt['hash'];
			trace.transactionPosition = receipt['trx_index'];
		}

		return trace;
	}

	function makeTraces(receipt, adHoc) {

		receipt['itxs'] = receipt['itxs'].filter(item => item.traceAddress.length > 0);
		const results = [
			makeInitialTrace(receipt, adHoc)
		];
		for (const itx of receipt['itxs']) {
			results.push(makeTrace(receipt, itx, adHoc));
		}

		if (!adHoc)
			return results;

		return {
			"output": addHexPrefix(receipt.output),
			"stateDiff": null,
			"trace": results,
			"vmTrace": null
		}
	}

	async function getTracesForTrx(trxHash, adHoc, client) {
		if (trxHash) {
			const receiptAction = await searchActionByHash(trxHash, client);
			if (!receiptAction) return null;
			const receipt = receiptAction['@raw'];

			if (receipt && receipt['itxs']) {
				return makeTraces(receipt, adHoc);
			} else {
				return null;
			}
		} else {
			return null;
		}
	}

	async function toBlockNumber(blockParam: string) {
		if (blockParam == "latest" || blockParam == "pending")
			return await getCurrentBlockNumber(true);

		if (blockParam == "earliest")
			return "0x0";

		if (typeof blockParam === 'number') {
			// We were passed a number, convert to hex string
			return addHexPrefix((blockParam as number).toString(16));
		} else if (!isHexPrefixed(blockParam)) {
			// Assume this is a number as string, missing the hex prefix, parse number and turn to hex string
			return addHexPrefix(parseInt(blockParam, 10).toString(16))
		} else {
			// We were given the proper format of a 0x prefixed hex value, return it
			return blockParam;
		}
	}


	// LOAD METHODS

	/**
	 * Returns the supported modules
	 */
	methods.set('rpc_modules', () => {
		return {
			"eth":"1.0",
			"net":"1.0",
			"trace":"1.0",
			"web3":"1.0"
		};
	})


	/**
	 * Returns the user-agent
	 */
	methods.set('web3_clientVersion', () => {
		// TODO: maybe figure out how to set this dynamically from a tag?
		return `TelosEVM/v1.0.0`;
	})

	/**
	 * Returns syncing info
	 */
	methods.set('eth_syncing', async () => {
		const syncingObj = {
			startingBlock: 0,
			currentBlock: parseInt(await getCurrentBlockNumber(true), 16),
			highestBlock: parseInt(await getCurrentBlockNumber(false), 16)
		}

		if ((syncingObj.highestBlock - syncingObj.currentBlock) > opts.syncingThreshhold)
			return syncingObj

		return false
	})

	/**
	 * Returns true if client is actively listening for network connections.
	 */
	methods.set('net_listening', () => true);

	/**
	 * Returns the current "latest" block number.
	 */
	methods.set('eth_blockNumber', async () => {
		try {
			return removeLeftZeros(await getCurrentBlockNumber(true));
		} catch (e) {
			throw new Error('Request Failed: ' + e.message);
		}
	});

	/**
	 * Returns the current network id.
	 */
	methods.set('net_version', () => CHAIN_ID);

	/**
	 * Returns the currently configured chain id, a value used in
	 * replay-protected transaction signing as introduced by EIP-155.
	 */
	methods.set('eth_chainId', () => CHAIN_ID_HEX);

	/**
	 * Returns a list of addresses owned by client.
	 */
	methods.set('eth_accounts', () => []);

	/**
	 * Returns current irreversible block
	 */
	methods.set('telos_finality', async () => {
		const getInfoResponse = await getInfo()
		const finalBlock = getInfoResponse.last_irreversible_block_num.value.add(new BN(opts.blockNumberDelta)).toNumber()
		const headBlock = getInfoResponse.head_block_num.value.toNumber()
		return { finalBlock, headBlock }
	})

	/**
	 * Returns a list of pending transactions
	 */
	methods.set('parity_pendingTransactions', () => []);

	/**
	 * Returns the number of transactions sent from an address.
	 */
	methods.set('eth_getTransactionCount', async ([address]) => {
		return removeLeftZeros(await fastify.evm.getNonce(address.toLowerCase()));
	});

	/**
	 * Returns the compiled smart contract code,
	 * if any, at a given address.
	 */
	methods.set('eth_getCode', async ([address]) => {
		try {
			const account = await fastify.evm.getEthAccount(address.toLowerCase());
			if (account.code && account.code.length > 0 && account.code !== "0x") {
				return addHexPrefix(Buffer.from(account.code).toString("hex"));
			} else {
				return "0x";
			}
		} catch (e) {
			return "0x";
		}
	});

	/**
	 * Returns the value from a storage position at a given address.
	 */
	methods.set('eth_getStorageAt', async ([address, position]) => {
		const value = await fastify.evm.getStorageAt(address.toLowerCase(), position);
		return (value === '0x0') ? '0x0000000000000000000000000000000000000000000000000000000000000000' : value;
	});

	/**
	 * Generates and returns an estimate of how much gas is necessary to
	 * allow the transaction to complete.
	 */
	methods.set('eth_estimateGas', async ([txParams, block]) => {
		if (txParams.hasOwnProperty('value')) {
			// If value is not 0 check there is an account first
			if(txParams.value > 0){
				const account = await fastify.evm.getEthAccount(txParams.from.toLowerCase());
				if (!account) {
					let err = new TransactionError('Insufficient funds');
					err.errorMessage = 'insufficient funds for gas * price + value';
					throw err;
				}
			}
			txParams.value = BigNumber.from(txParams.value).toHexString().slice(2);
		}

		const encodedTx = await fastify.evm.createEthTx({
			...txParams,
			sender: txParams.from,
			gasPrice: 10000000000000000,
			gasLimit: 10000000000000000
		});

		try {
			const gas = await fastify.evm.estimateGas({
				account: opts.signerAccount,
				ram_payer: fastify.evm.telosContract,
				tx: encodedTx,
				sender: txParams.from,
				trxVars: await makeTrxVars(),
				getInfoResponse: await getInfo()
			});

			if (gas.startsWith(REVERT_FUNCTION_SELECTOR) || gas.startsWith(REVERT_PANIC_SELECTOR)) {
				handleGasEstimationError(gas);
			}

			if (gas === '0x') {
				let err = new TransactionError('Transaction reverted');
				err.errorMessage = `execution reverted: no output`;
				err.data = gas;
				throw err;
			}

			let toReturn = `${Math.ceil((parseInt(gas, 16) * GAS_OVER_ESTIMATE_MULTIPLIER)).toString(16)}`;
			Logger.debug(`From contract, gas estimate is ${gas}, with multiplier returning ${toReturn}`)
			return removeLeftZeros(toReturn);
		} catch (e) {
			if(e.receipt){
				handleGasEstimationError(e.receipt);
			}
            // These are changes from yeet_eosjs
            /*
			console.dir(e);
			if (e?.receipt?.output !== undefined)
				 handleGasEstimationError(e?.receipt?.output);
			else
				throw new Error(`Failure while estimating gas: ${e.message}`)
             */
		}
	});

	function handleGasEstimationError(receipt) {
		let err = new TransactionError('Transaction reverted');
		err.data = receipt.output;

		let output = addHexPrefix(receipt.output);

		if (output.startsWith(REVERT_FUNCTION_SELECTOR)) {
			err.errorMessage = `execution reverted: ${parseRevertReason(output)}`;
		} else if (output.startsWith(REVERT_PANIC_SELECTOR)) {
			err.errorMessage = `execution reverted: ${parsePanicReason(output)}`;
		} else {
			if(receipt.errors.length > 0){
				err.errorMessage = `execution reverted: `;
				for(let i in receipt.errors){
					err.errorMessage += receipt.errors[i] + ', ';
				}
				err.errorMessage = err.errorMessage.slice(0, -2);
			} else {
				err.errorMessage = `execution reverted without reason provided`;
			}
		}

		throw err;
	}

	/**
	 * Returns the current gas price in wei.
	 */
	methods.set('eth_gasPrice', async () => {
		const key = `${CACHE_PREFIX}_gas_price`;
		const cachedData = await fastify.redis.get(key);
        if (cachedData) {
            return cachedData;
        } else {
            let price = await fastify.evm.getGasPrice();
            let priceInt = parseInt(price, 16) * GAS_PRICE_OVERESTIMATE;
            const gasPrice = isNaN(priceInt) ? null : removeLeftZeros(Math.floor(priceInt).toString(16));
            fastify.redis.set(key, gasPrice, {
				PX: 500
			});
			return gasPrice;
		}
	});

	/*
	 * Returns the balance of the account of given address.
	 */
	methods.set('eth_getBalance', async ([address]) => {
		try {
			const account = await fastify.evm.getEthAccount(address.toLowerCase());
			if (!account) {
				return "0x0";
			}
			const bal = account.balance;
			return removeLeftZeros(bal.toString(16));
		} catch (e) {
			return "0x0";
		}
	});

	/**
	 * Returns the balance in native tokens (human readable format)
	 * of the account of given address.
	 */
	methods.set('eth_getBalanceHuman', async ([address]) => {
		try {
			const account = await fastify.evm.getEthAccount(address.toLowerCase());
			if (!account) {
				return "0";
			}
			const bal = account.balance as typeof BN;
			// @ts-ignore
			const balConverted = bal / decimalsBN;
			return balConverted.toString(10);
		} catch (e) {
			return "0";
		}
	});

	/**
	 * Executes a new message call immediately without creating a
	 * transaction on the block chain.
	 */
	methods.set('eth_call', async ([txParams]) => {
		let _value = ethers.BigNumber.from(0);
		if (txParams.value) {
			_value = ethers.BigNumber.from(txParams.value);
		}
		const obj = {
			...txParams,
			value: _value.toHexString().replace(/^0x/, ''),
			sender: txParams.from,
		};
		let tx = await fastify.evm.createEthTx(obj);
		let sender = txParams.from

		if (tx && isHexPrefixed(tx)) tx = tx.substring(2)
		if (sender && isHexPrefixed(sender)) sender = sender.substring(2)

		if (sender && sender === '')
			sender = undefined

		const action = {
			account: 'eosio.evm',
			name: 'call',
			authorization: [
				{
					actor: fastify.rpcAccount,
					permission: fastify.rpcPermission,
				},
			],
			data: Call.from({
				ram_payer: fastify.rpcAccount,
				estimate_gas: false,
				tx, sender
			})
		}
		try {
			const info = await getInfo()
			const transaction = Transaction.from({
				...info.getTransactionHeader(120),
				actions: [
					action
				],
			})
			const key = PrivateKey.from(fastify.rpcKey)
			const signature = key.signDigest(transaction.signingDigest(info.chain_id))
			const signedTransaction = SignedTransaction.from({
				...transaction,
				signatures: [signature],
			})
			// const sendResult = await fastify.readApi.v1.chain.push_transaction(signedTransaction)
			// const sendResult = await fastify.readApi.v1.chain.send_transaction2(signedTransaction)
			const sendResult = await fastify.readApi.v1.chain.send_transaction(signedTransaction) as any
		} catch (e) {
			const error = e.response.json.error
			if (error.code !== 3050003) {
				throw new Error('This node does not have console printing enabled')
			}
			const message = error.details[1].message
			const resultMatch = message.match(/(0[xX][0-9a-fA-F]*)$/)
			if (resultMatch) {
				const result = resultMatch[0];
				const REVERT = "REVERT";
				const revertLength = REVERT.length;
				const startResult = message.length - result.length;
				const beforeResult = message.substring((startResult - revertLength), startResult);
				if (beforeResult === REVERT) {
					let output = "0x" + (result.replace(/^0x/, ''));
					let err = new TransactionError('Transaction reverted');
					err.data = output;
					if (output.startsWith(REVERT_FUNCTION_SELECTOR)) {
						err.errorMessage = `VM Exception while processing transaction: reverted with reason string: ${parseRevertReason(output)}`;
					} else if (output.startsWith(REVERT_PANIC_SELECTOR)) {
						err.errorMessage = `VM Exception while processing transaction: panicked with reason: ${parsePanicReason(output)}`;
					} else {
						err.errorMessage = 'VM Exception while processing transaction: reverted without a reason string';
					}
					throw err;
				}

				return leftPadZerosEvenBytes(result);
			}

			let defaultMessage = `Server error during call: ${e.message}`
			throw new Error(defaultMessage)
		}
	});

	/**
	 * Submits a pre-signed transaction for broadcast to the
	 * Ethereum network.
	 */
	methods.set('eth_sendRawTransaction', async ([signedTx]) => {
		try {
			const rawResponse = await fastify.evm.raw({
				account: opts.signerAccount,
				tx: signedTx,
				ram_payer: fastify.evm.telosContract,
				trxVars: await makeTrxVars(),
				getInfoResponse: await getInfo()
			});

			let consoleOutput = rawResponse.telos.processed.action_traces[0].console;

			let receiptLog = consoleOutput.slice(consoleOutput.indexOf(RECEIPT_LOG_START) + RECEIPT_LOG_START.length, consoleOutput.indexOf(RECEIPT_LOG_END));
			let receipt = JSON.parse(receiptLog);
			// This error handling looks wrong, we should not be throwing errors like this directly for everything...
			if (receipt.status === 0) {
				let err = new TransactionError('Transaction error');
				let output = addHexPrefix(receipt.output);
				if (output.startsWith(REVERT_FUNCTION_SELECTOR)) {
					err.errorMessage = `VM Exception while processing transaction: reverted with reason string: ${parseRevertReason(output)}`;
				} else if (output.startsWith(REVERT_PANIC_SELECTOR)) {
					err.errorMessage = `VM Exception while processing transaction: panicked with reason: ${parsePanicReason(output)}`;
				} else {
					// Borrowed message from hardhat node
					if (receipt?.errors?.length > 0 && receipt.errors[0].toLowerCase().indexOf('revert') !== -1)
						err.errorMessage = `Transaction reverted: No reason string given.`;
					else
						err.errorMessage = `VM Exception while processing transaction: ${receipt?.errors[0]}`;
				}

				err.data = {
					txHash: addHexPrefix(rawResponse.eth.transactionHash)
				};
				throw err;
			}

			return addHexPrefix(rawResponse.eth.transactionHash);
		} catch (e) {
			if (opts.orderNonces) {
                // The previous version with eosjs was:
                // const assertionMessage = e?.details[0]?.message
				const assertionMessage = e?.response?.json?.error?.details[0]?.message
				if (assertionMessage && assertionMessage.includes('incorrect nonce')) {
					return nonceRetryManager.submitFailedRawTrx(signedTx);
				}
            }

            if (e instanceof TransactionError)
                throw e;

			throw e;
		}
	});

	/**
	 * Submits transaction for broadcast to the Ethereum network.
	 */
	methods.set('eth_sendTransaction', async ([txParams]) => {
		throw new Error(`No private key available to sign transaction`)
	});

	/**
	 * Returns the receipt of a transaction by transaction hash.
	 */
	methods.set('eth_getTransactionReceipt', async ([trxHash, client]) => {
		if (trxHash) {

			// lookup receipt delta
			//const receiptDelta = await searchDeltasByHash(trxHash);
			//if (!receiptDelta) return null;
			//const receipt = receiptDelta['@receipt'];

			// lookup receipt action
			const receiptAction = await searchActionByHash(trxHash, client);
			if (!receiptAction) return null;
			const receipt = receiptAction['@raw'];

			//Logger.debug(`get transaction receipt got ${JSON.stringify(receipt)}`)
			const _blockHash = addHexPrefix(receipt['block_hash']);
			const _blockNum = numToHex(receipt['block']);
			const _gas = numToHex(receipt['gasused']);
			let _contractAddr = null;
			if (receipt['createdaddr']) {
				_contractAddr = addHexPrefix(receipt['createdaddr']);
			}
			let _logsBloom = EMPTY_LOGS;
			if (receipt['logsBloom']) {
				_logsBloom = addHexPrefix(receipt['logsBloom']);
			}

			return {
				blockHash: _blockHash,
				blockNumber: removeLeftZeros(numToHex(receipt['block'])),
				contractAddress: toChecksumAddress(_contractAddr),
				cumulativeGasUsed: removeLeftZeros(_gas),
				from: toChecksumAddress(receipt['from']),
				gasUsed: removeLeftZeros(_gas),
				logsBloom: _logsBloom,
				status: removeLeftZeros(numToHex(receipt['status'])),
				to: toChecksumAddress(receipt['to']),
				transactionHash: receipt['hash'],
				transactionIndex: removeLeftZeros(numToHex(receipt['trx_index'])),
				logs: buildLogsObject(
					receipt['logs'],
					_blockHash,
					_blockNum,
					receipt['hash'],
					numToHex(receipt['trx_index'])
				),
				//errors: receipt['errors'],
				//output: '0x' + receipt['output']
			};
		} else {
			return null;
		}
	});

	/**
	 * Returns information about a transaction for a given hash.
	 */
	methods.set('eth_getTransactionByHash', async ([trxHash, client]) => {
		// lookup raw action
		const receiptAction = await searchActionByHash(trxHash, client);
		if (!receiptAction) return null;
		const {v, r, s} = await getVRS(receiptAction);
		const receipt = receiptAction['@raw'];

		// lookup receipt delta
		//const receiptDelta = await searchDeltasByHash(trxHash);
		//if (!receiptDelta) return null;
		//const receipt = receiptDelta['@receipt'];

		const _blockHash = addHexPrefix(receipt['block_hash']);
		const _blockNum = numToHex(receipt['block']);
		return {
			blockHash: _blockHash,
			blockNumber: removeLeftZeros(_blockNum),
			from: toChecksumAddress(receipt['from']),
			gas: removeLeftZeros(numToHex(receipt.gas_limit)),
			gasPrice: removeLeftZeros(numToHex(receipt.charged_gas_price)),
			hash: receipt['hash'],
			input: receipt['input_data'],
			nonce: removeLeftZeros(numToHex(receipt['nonce'])),
			to: toChecksumAddress(receipt['to']),
			transactionIndex: removeLeftZeros(numToHex(receipt['trx_index'])),
			value: removeLeftZeros(receipt['value']),
			v: removeLeftZeros(v),
			r, s
		};
	});

	/**
	 * Returns information about a block by number.
	 */
	methods.set('eth_getBlockByNumber', async ([block, full, client]) => {
		const blockNumber = parseInt(await toBlockNumber(block), 16);
		
		if (blockNumber === 0)
			return GENESIS_BLOCK;
		

		const blockDelta = await getDeltaDocFromNumber(blockNumber);
		if (blockDelta['@transactionsRoot'] === NULL_TRIE)
			return emptyBlockFromDelta(blockDelta);

		const receipts = await getReceiptsByTerm("@raw.block", blockNumber);
		return receipts.length > 0 ? await reconstructBlockFromReceipts(receipts, full, client) : await emptyBlockFromNumber(blockNumber);
	});

	/**
	 * Returns information about a block by hash.
	 */
	methods.set('eth_getBlockByHash', async ([hash, full, client]) => {
		let _hash = hash.toLowerCase();
		if (_hash === GENESIS_BLOCK_HASH)
			return GENESIS_BLOCK;

		if (isHexPrefixed(_hash)) {
			_hash = _hash.slice(2);
		}
		const receipts = await getReceiptsByTerm("@raw.block_hash", _hash);
		return receipts.length > 0 ? await reconstructBlockFromReceipts(receipts, full, client) : await emptyBlockFromHash(_hash);
	});

	/**
	 * Returns the number of transactions in the block with
	 * the given block hash.
	 */
	methods.set('eth_getBlockTransactionCountByHash', async ([hash]) => {
		let _hash = hash.toLowerCase();
		if (isHexPrefixed(_hash)) {
			_hash = _hash.slice(2);
		}
		const receipts = await getReceiptsByTerm("@raw.block_hash", _hash);
		const txCount: number = receipts.length;
		return removeLeftZeros(txCount.toString(16));
	});

	/**
	 * Returns the number of transactions in the block with
	 * the given block number.
	 */
	methods.set('eth_getBlockTransactionCountByNumber', async ([block]) => {
		const blockNumber = parseInt(block, 16);
		const receipts = await getReceiptsByTerm("@raw.block", blockNumber);
		const txCount: number = receipts.length;
		return removeLeftZeros(txCount.toString(16));
	});

	/**
	 * Returns the number of uncles in a block from a block
	 * matching the given block hash.
	 */
	methods.set('eth_getUncleCountByBlockHash', () => "0x0");

	/**
	 * Returns the number of uncles in a block from a block
	 * matching the given block number.
	 */
	methods.set('eth_getUncleCountByBlockNumber', () => "0x0");

	/**
	 * Returns an array of all logs matching a given filter object.
	 */
	methods.set('eth_getLogs', async ([parameters, client]) => {
		let params = await parameters; // Since we are using async/await, the parameters are actually a Promise
		//Logger.debug(params);

		const queryBody: any = {
			bool: {
				must: [
					{ exists: { field: "@raw.logs" } }
				]
			}
		};

		// query preparation
		let addressFilter: string | string[] = params.address;
		let topicsFilter: string[] = params.topics;
		let blockHash: string = params.blockHash;
		let fromBlock: string | number;
		let toBlock: string | number;

		if (blockHash) {
			if (isHexPrefixed(blockHash)) {
				blockHash = blockHash.slice(2)
			}

			if (params.fromBlock || params.toBlock) {
				throw new Error('fromBlock/toBlock are not allowed with blockHash query');
			}
			queryBody.bool.must.push({ term: { "@raw.block_hash": blockHash } })
		} else {

			let fromBlockExplicit = await toBlockNumber(params.fromBlock || 'latest');
			fromBlock = typeof(fromBlockExplicit) == 'string' ? parseInt(fromBlockExplicit, 16) : fromBlockExplicit;
			let toBlockExplicit = await toBlockNumber(params.toBlock || 'latest')
			toBlock = typeof(toBlockExplicit) == 'string' ? parseInt(toBlockExplicit, 16) : toBlockExplicit;

			/*
            // TODO: Test this, seems a logical thing to add.
            if (fromBlock == toBlock) {
                queryBody.bool.must.push({ term: { "@raw.block": fromBlock } })
            } else {... the below
             */
			const rangeObj = { range: { "@raw.block": {} } };
			if (fromBlock) {
				// Logger.debug(`getLogs using fromBlock: ${fromBlock}`);
				rangeObj.range["@raw.block"]['gte'] = fromBlock;
			}
			if (toBlock) {
				// Logger.debug(`getLogs using toBlock: ${toBlock}`);
				rangeObj.range["@raw.block"]['lte'] = toBlock;
			}
			queryBody.bool.must.push(rangeObj);
		}

		if (addressFilter) {
			if (Array.isArray(addressFilter)) {
				if (addressFilter.length > 0) {
					const nestedOr = {bool: {should: []}};

					addressFilter = addressFilter.map(addr => {
						if (isHexPrefixed(addr))
							addr = addr.slice(2);

						return addr.toLowerCase();
					});

					addressFilter.forEach(addr => {
						if (!addr)
							return;

						nestedOr.bool.should.push({term: {"@raw.logs.address": addr}})
					})
					queryBody.bool.must.push(nestedOr);
				}
			} else {
				addressFilter = addressFilter.toLowerCase();
				if (isHexPrefixed(addressFilter)) {
					addressFilter = addressFilter.slice(2);
				}
				//Logger.debug(`getLogs using address: ${addressFilter}`);
				queryBody.bool.must.push({term: {"@raw.logs.address": addressFilter}})
			}
		}

		if (topicsFilter && topicsFilter.length > 0) {
			let flatTopics = [];
			//Logger.debug(`getLogs using raw topics:\n${topicsFilter}`);
			topicsFilter.forEach((topic, index) => {
				if (!topic)
					return;

				//console.debug(`topic: ${topic}`);
				let trimmed = removeZeroHexFromFilter(topic, false);
				//console.debug(`topic trimmed: ${trimmed}`);

				if (Array.isArray(trimmed)) {
					// Todo: make or query by index
					trimmed.forEach(t => flatTopics.push(t));
				} else {
					flatTopics.push(trimmed);
				}
			})
			//Logger.debug(`getLogs using topics:\n${topicsFilter}`);
			queryBody.bool.must.push({
				terms: {
					"@raw.logs.topics": flatTopics,
				}
			})
		}

		// search
		try {
			const searchResults = await fastify.elastic.search({
				index: `${opts.elasticIndexPrefix}-action-${opts.elasticIndexVersion}-*`,
				size: 2000,
				query: queryBody,
				sort: [{ "@raw.block": { order: "asc" }, "@raw.trx_index": {order: "asc"} }]
			});

			// processing
			const results = [];
			for (const hit of searchResults.hits.hits) {
				const doc = hit._source;
				if (doc['@raw'] && doc['@raw']['logs']) {
					let logCount = 0;
					for (const log of doc['@raw']['logs']) {
						const block = doc['@raw']['block'];
						log.logIndex = logCount;
						logCount++;

						if (!blockHash) {
							if (fromBlock > block || toBlock < block) {
								// Logger.debug('filter out by from/to block');
								continue;
							}
						} else {
							if (blockHash !== doc['@raw']['block_hash']) {
								// Logger.debug('filter out by blockHash');
								continue;
							}
						}

						if (!logFilterMatch(log, addressFilter, topicsFilter))
							continue;

						results.push(makeLogObject(doc, log, false));
					}
				}
			}

			return results;
		} catch (e) {
			Logger.error(`${client.ip} - ERROR while filtering log query result: ${e.message}`);
			return [];
		}
	});

	/**
	 * Returns the internal transaction trace filter matching the given filter object.
	 * https://openethereum.github.io/JSONRPC-trace-module#trace_filter
	 * curl --data '{"method":"trace_filter","params":[{"fromBlock":"0x2ed0c4","toBlock":"0x2ed128","toAddress":["0x8bbB73BCB5d553B5A556358d27625323Fd781D37"],"after":1000,"count":100}],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:7000/evm
	 *
	 * Check the eth_getlogs function above for help
	 */
    methods.set('trace_filter', async ([parameters, client]) => {
        let params = await parameters;
        const run = async function(paramObject){
            const results = [];
            let fromAddress = paramObject.fromAddress;
            let toAddress = paramObject.toAddress;
            let fromBlock: string | number = parseInt(await toBlockNumber(paramObject.fromBlock), 16);
            let toBlock: string | number = parseInt(await toBlockNumber(paramObject.toBlock), 16);
            let after:  number = paramObject.after; //TODO what is this?
            let count: number = paramObject.count;

            if (typeof fromAddress !== 'undefined') {
                fromAddress.forEach((addr, index) => fromAddress[index] = toChecksumAddress(addr).slice(2).replace(/^0+/, '').toLowerCase());
            }
            if (typeof toAddress !== 'undefined') {
                toAddress.forEach((addr, index) => toAddress[index] = toChecksumAddress(addr).slice(2).replace(/^0+/, '').toLowerCase());
            }

            const queryBody: any = {
                bool: {
                    must: [
                        { exists: { field: "@raw.itxs" } }
                    ]
                }
            };

            if (fromBlock || toBlock) {
                const rangeObj = { range: { "@raw.block": {} } };
                if (fromBlock) {
                    // Logger.debug(`getLogs using toBlock: ${toBlock}`);
                    rangeObj.range["@raw.block"]['gte'] = fromBlock;
                }
                if (toBlock) {
                    // Logger.debug(`getLogs using fromBlock: ${params.fromBlock}`);
                    rangeObj.range["@raw.block"]['lte'] = toBlock;
                }
                queryBody.bool.must.push(rangeObj);
            }

            if (fromAddress) {
                // Logger.debug(fromAddress);
                const matchFrom = { terms: { "@raw.itxs.from": {} } };
                matchFrom.terms["@raw.itxs.from"] = fromAddress;
                queryBody.bool.must.push(matchFrom);
            }
            if (toAddress) {
                // Logger.debug(toAddress);
                const matchTo = { terms: { "@raw.itxs.to": {} } };
                matchTo.terms["@raw.itxs.to"] = toAddress;
                queryBody.bool.must.push(matchTo);
            }

            // search
            try {
                const searchResults = await fastify.elastic.search({
                    index: `${opts.elasticIndexPrefix}-action-${opts.elasticIndexVersion}-*`,
                    size: count,
                    query: queryBody,
                    sort: [{ "@raw.trx_index": { order: "asc" } }]
                });

                // processing
                let logCount = 0;
                for (const hit of searchResults.hits.hits) {
                    const doc = hit._source;
                    if (doc['@raw'] && doc['@raw']['itxs']) {
                        for (const itx of doc['@raw']['itxs']) {
                            results.push({
                                action: {
                                    callType: toOpname(itx.callType),
                                    //why is 0x not in the receipt table?
                                    from: toChecksumAddress(itx.from),
                                    gas: addHexPrefix(itx.gas),
                                    input: addHexPrefix(itx.input),
                                    to: toChecksumAddress(itx.to),
                                    value: addHexPrefix(itx.value)
                                },
                                blockHash: addHexPrefix(doc['@raw']['block_hash']),
                                blockNumber: doc['@raw']['block'],
                                result: {
                                    gasUsed: addHexPrefix(itx.gasUsed),
                                    output: addHexPrefix(itx.output),
                                },
                                subtraces: itx.subtraces,
                                traceAddress: itx.traceAddress,
                                transactionHash: addHexPrefix(doc['@raw']['hash']),
                                transactionPosition: doc['@raw']['trx_index'],
                                type: itx.type
                            });
                            logCount++;
                        }
                    }
                }
            } catch (e) {
                Logger.error(client.ip + ' - ' + JSON.stringify(e, null, 2));
                return [];
            }
            return results;
        }
        if(Array.isArray(params)){
            const results = [];
            for (const param_obj of params) {
                results.concat(run(param_obj));
            }
            return results;
        } else {
            return run(params);
        }
    });

	/**
	 * Returns the internal transaction trace filter matching the given filter object.
	 * https://openethereum.github.io/JSONRPC-trace-module#trace_transaction
	 * curl --data '{"method":"trace_transaction","params":["0x17104ac9d3312d8c136b7f44d4b8b47852618065ebfa534bd2d3b5ef218ca1f3"],"id":1,"jsonrpc":"2.0"}' -H "Content-Type: application/json" -X POST localhost:7000/evm
	 */
	methods.set('trace_transaction', async ([trxHash, client]) => {
		return await getTracesForTrx(trxHash, false, client);
	});

	/*
        {
         "id": 1,
         "jsonrpc": "2.0",
         "result": {
           "output": "0x",
           "stateDiff": null,
           "trace": [{
             "action": { ... },
             "result": {
               "gasUsed": "0x0",
               "output": "0x"
             },
             "subtraces": 0,
             "traceAddress": [],
             "type": "call"
           }],
           "vmTrace": null
         }
       }

     */
	methods.set('trace_replayTransaction', async ([trxHash, traceTypes, client]) => {
		if (traceTypes.length !== 1 || traceTypes[0] !== 'trace')
			throw new Error("trace_replayTransaction only supports the \"trace\" type of trace (not vmTrace or stateDiff");

		return getTracesForTrx(trxHash, true, client);
	});

	/*
	{
	  "id": 1,
	  "jsonrpc": "2.0",
	  "result": [
		{
		  "output": "0x",
		  "stateDiff": null,
		  "trace": [{
			"action": { ... },
			"result": {
			  "gasUsed": "0x0",
			  "output": "0x"
			},
			"subtraces": 0,
			"traceAddress": [],
			"type": "call"
		  }],
		  "transactionHash": "0x...",
		  "vmTrace": null
		},
		{ ... }
	  ]
	}

	 */

	methods.set('trace_replayBlockTransactions', async ([block, traceTypes]) => {
		if (traceTypes.length !== 1 || traceTypes[0] !== 'trace')
			throw new Error("trace_replayBlockTransactions only supports the \"trace\" type of trace (not vmTrace or stateDiff");

		const blockNumber = parseInt(await toBlockNumber(block), 16);
		const receiptHits = await getReceiptsByTerm("@raw.block", blockNumber);
		const receipts = receiptHits.map(r => r._source["@raw"]);
		const sortedReceipts = receipts.sort((a, b) => {
			return a.trx_index - b.trx_index;
		})
		let transactions = []
		for (let i = 0; i < sortedReceipts.length; i++) {
			let receipt = sortedReceipts[i];
			let trx: any = makeTraces(receipt, true);
			trx.transactionHash = receipt.hash;
			transactions.push(trx);
		}
		return transactions;
	});


	methods.set('trace_block', async ([block]) => {
		const blockNumber = parseInt(await toBlockNumber(block), 16);
		const receiptHits = await getReceiptsByTerm("@raw.block", blockNumber);
		const receipts = receiptHits.map(r => r._source["@raw"]);
		const sortedReceipts = receipts.sort((a, b) => {
			return a.trx_index - b.trx_index;
		})
		let traces = []
		for (let i = 0; i < sortedReceipts.length; i++) {
			let receipt = sortedReceipts[i];
			let trxTraces: any = makeTraces(receipt, false);
			traces.concat(traces, trxTraces);
		}
		return traces;
	});


	/*
	// TODO: once we understand what the index position is...
	methods.set('trace_get', async ([block, indexPositions]) => {
		const blockNumber = parseInt(await toBlockNumber(block), 16);
		const receipts = await getReceiptsByTerm("@raw.block", blockNumber);
		if (indexPositions.length !== 1)
			return null;

		let indexPosition = indexPositions[0];
		for (let i = 0; i < receipts.length; i++) {
			if (receipts[i].... == indexPosition)
				return receipts[i]...
		}
		return null;
	});
	*/

	// END METHODS

	/**
	 * Main JSON RPC 2.0 Endpoint
	 */

	const schema: any = {
		summary: 'EVM JSON-RPC 2.0',
		tags: ['evm'],
	};

	async function doRpcMethod(jsonRpcRequest: any, clientInfo, reply: any) {
		let { jsonrpc, id, method, params } = jsonRpcRequest;
		let { usage, limit, origin, ip } = clientInfo;
		if(!params || !Array.isArray(params)){
			params = [];
		}
		params.push(clientInfo);

		// if jsonrpc not set, assume 2.0 as there are some clients which leave it out
		if (!jsonrpc)
			jsonrpc = "2.0"

		if (jsonrpc !== "2.0") {
			Logger.error(`REQERROR: ${new Date().toISOString()} - ${ip} - Got invalid jsonrpc, request.body was: ${JSON.stringify(jsonRpcRequest, null, 4)}`);
			return jsonRPC2Error(reply, "InvalidRequest", id, "Invalid JSON RPC");
		}
		if (methods.has(method)) {
			const tRef = process.hrtime.bigint();
			const func = methods.get(method);
			try {
                /*
				 // 1 = lib lag
				 if (healthStatus === 1) {
					 const code = 3
					 const data = await getInfo()
					 const message = `ERROR: Node fork detected`
					 const error = { code, data, message }
					 console.log(`RPCERROR: ${new Date().toISOString()} - ${ip} - ${JSON.stringify({error})} | Method: ${method} | REQ: ${JSON.stringify(params)}`);
					 return {jsonrpc, id, error};
				 }

				 // 2 = head lag
				 if (healthStatus === 2) {
					 const code = 3
					 const data = await getInfo()
					 const message = `ERROR: Node out of sync detected`
					 const error = { code, data, message }
					 console.log(`RPCERROR: ${new Date().toISOString()} - ${ip} - ${JSON.stringify({error})} | Method: ${method} | REQ: ${JSON.stringify(params)}`);
					 return {jsonrpc, id, error};
				 }
                 */
				const result = await func(params);

				const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
				Logger.log(`RPCREQUEST: ${new Date().toISOString()} - ${duration} μs - ${ip} (${isNaN(usage) ? 0 : usage}/${isNaN(limit) ? 0 : limit}) - ${origin} - ${method}`);
				Logger.debug(`REQ: ${JSON.stringify(params)} | RESP: ${typeof result == 'object' ? JSON.stringify(result, null, 2) : result}`);
				return { jsonrpc, id, result };
			} catch (e) {
				if (e instanceof TransactionError) {
					let code = e.code || 3;
					let message = e.errorMessage?.replace(/\0.*$/g,'');;
					let data = e.data;
					let error = { code, data, message };
					Logger.error(`RPCREVERT: ${new Date().toISOString()} - ${ip} | Method: ${method} | VM execution error, reverted with message: ${e.errorMessage} \n\n REQ: ${JSON.stringify(params)}\n\n ERROR RESP: ${JSON.stringify(error)}`);
					return { jsonrpc, id, error };
				}

				let error: any = { code: 3 };
				if (e?.json?.error?.code === 3050003) {
					let message = e?.json?.error?.details[0]?.message;

					if (message.startsWith(EOSIO_ASSERTION_PREFIX))
						message = message.substr(EOSIO_ASSERTION_PREFIX.length, message.length + 1);

					error.message = message;
				} else {
					error.message = e?.message;
				}

				Logger.error(`RPCERROR: ${new Date().toISOString()} - ${ip} - ${JSON.stringify({error, exception: e})} | Method: ${method} | REQ: ${JSON.stringify(params)}`);
				return { jsonrpc, id, error };
			}
		} else {
			Logger.error(`METHODNOTFOUND: ${new Date().toISOString()} - ${ip} - ${method}`);
			return jsonRPC2Error(reply, 'MethodNotFound', id, `Invalid method: ${method}`);
		}
	}

	async function doRpcPayload(payload, clientInfo, reply) {
		const { ip, origin, usage, limit } = clientInfo;
		if (Array.isArray(payload)) {
			if (payload.length == 0)
				return

			const tRef = process.hrtime.bigint();

			let promises = [];
			for (let i = 0; i < payload.length; i++) {
				let promise = doRpcMethod(payload[i], clientInfo, reply);
				promises.push(promise);
			}
			let responses = await Promise.all(promises);

			const duration = ((Number(process.hrtime.bigint()) - Number(tRef)) / 1000).toFixed(3);
			Logger.log(`RPCREQUESTBATCH: ${new Date().toISOString()} - ${duration} μs - ${ip} (${usage}/${limit}) - ${origin} - BATCH OF ${responses.length}`);
			return responses;
		} else {
			return await doRpcMethod(payload, clientInfo, reply);
		}
	}

	fastify.rpcPayloadHandlerContainer.handler = doRpcPayload;

	fastify.get('/evm', { schema }, async (req, reply) => {
		const block = await methods.get('eth_getBlockByNumber')(['latest', false]);
		reply.send({
			name: opts.nodeName,
			message: 'This is a TelosEVM JSON-RPC endpoint.  The JSON-RPC 2.0 standard only uses HTTP POST, this response is purely informational.',
			chainId: opts.chainId,
			latestBlock: parseInt(block.number, 16).toString(10),
			timeBehind: moment(parseInt(block.timestamp, 16) * 1000).fromNow()
		})
	})

	fastify.post('/evm', { schema }, async (request: FastifyRequest, reply: FastifyReply) => {
		let origin;
		//Logger.debug(request.headers);
		if (request.headers['origin'] === METAMASK_EXTENSION_ORIGIN) {
			origin = 'MetaMask';
		} else {
			if (request.headers['origin']) {
				origin = request.headers['origin'];
			} else {
				origin = request.headers['user-agent'];
			}
		}
		const usage = parseInt(String(reply.getHeader('x-ratelimit-remaining')));
		const limit = parseInt(String(reply.getHeader('x-ratelimit-limit')));
		let ip = request.headers['x-forwarded-for'] || '';
		if (Array.isArray(ip))
			ip = ip[0] || ''

		if (ip.includes(','))
			ip = ip.substr(0, ip.indexOf(','));

		const clientInfo = {
			ip, origin, usage, limit
		}

		return await doRpcPayload(request.body, clientInfo, reply);
	});
}
