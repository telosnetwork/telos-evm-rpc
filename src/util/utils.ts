const createKeccakHash = require('keccak')
const BN = require('bn.js');

export interface EthLog {
    address: string;
    blockHash: string;
    blockNumber: string;
    data: string;
    logIndex: string;
    removed: boolean;
    topics: string[];
    transactionHash: string;
    transactionIndex: string;
}

export const NULL_HASH = '0x0000000000000000000000000000000000000000000000000000000000000000';
const ZERO_ADDR = '0x0000000000000000000000000000000000000000';
const KECCAK256_RLP_ARRAY = '0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347';

export const NULL_TRIE = '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421';

const EMPTY_LOGS = '0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000';

export const BLOCK_GAS_LIMIT = '0x7fffffff'

export const GENESIS_BLOCKS = {
    "0x28": {
        "difficulty": "0x0",
        "extraData": "0x00000024796a9998ec49fb788de51614c57276dc6151bd2328305dba5d018897",
        "gasLimit": "0x7fffffff",
        "gasUsed": "0x0",
        "hash": "0x36fe7024b760365e3970b7b403e161811c1e626edd68460272fcdfa276272563",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "miner": "0x0000000000000000000000000000000000000000",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "0x0000000000000000",
        "number": "0x0",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x21d",
        "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "timestamp": "0x5c114972",
        "totalDifficulty": "0x0",
        "transactions": [],
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "uncles": []
    },
    "0x29": {
        "difficulty": "0x0",
        "extraData": "0x000000397128c497668c241b27d1521c764156cea50bcac87892fc8916e23b24",
        "gasLimit": "0x7fffffff",
        "gasUsed": "0x0",
        "hash": "0xb25034033c9ca7a40e879ddcc29cf69071a22df06688b5fe8cc2d68b4e0528f9",
        "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "miner": "0x0000000000000000000000000000000000000000",
        "mixHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "nonce": "0x0000000000000000",
        "number": "0x0",
        "parentHash": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "receiptsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "size": "0x21d",
        "stateRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "timestamp": "0x5d55db93",
        "totalDifficulty": "0x0",
        "transactions": [],
        "transactionsRoot": "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        "uncles": []
    }
}

const NEW_HEADS_TEMPLATE =
    {
        difficulty: "0x0",
        extraData: NULL_HASH,
        gasLimit: BLOCK_GAS_LIMIT,
        miner: ZERO_ADDR,
        nonce: "0x0000000000000000",
        parentHash: NULL_HASH,
        receiptsRoot: NULL_TRIE,
        sha3Uncles: KECCAK256_RLP_ARRAY,
        stateRoot: NULL_TRIE,
        transactionsRoot: NULL_TRIE,
    };

const BLOCK_TEMPLATE =
    Object.assign({
        mixHash: NULL_HASH,
        size: "0x21e",
        totalDifficulty: "0x0",
        uncles: []
    }, NEW_HEADS_TEMPLATE);

export { BLOCK_TEMPLATE, NEW_HEADS_TEMPLATE, EMPTY_LOGS }

export function numToHex(input: number | string | Uint8Array | Uint8Array[]) : string {
    if (typeof input === 'number') {
        return '0x' + input.toString(16)
    } else if (typeof input === 'string') {
        return '0x' + new BN(input).toString(16)
    } else if (input instanceof Uint8Array) {
        return uInt8ArraytoHex(input);
    } else if (Array.isArray(input)) {
        return uInt8ArrayArrayHexArray(input);
    }
}
export function uInt8ArraytoHex(uint8Array: Uint8Array) {
    return Array.from(uint8Array)
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

export function uInt8ArrayArrayHexArray(uint8ArrayArray :  Uint8Array[]) {
    return uint8ArrayArray.map(uInt8ArraytoHex).join('');
}

export function toLowerCaseAddress(address) {
    if (!address)
        return null

    address = address.toLowerCase().replace('0x', '')
    if (address.length != 40)
        address = address.padStart(40, "0");

    return `0x${address}`
}

export function toChecksumAddress(address) {
    if (!address)
        return null

    address = address.toLowerCase().replace('0x', '')
    if (address.length != 40)
        address = address.padStart(40, "0");

    let hash = createKeccakHash('keccak256').update(address).digest('hex')
    let ret = '0x'

    for (var i = 0; i < address.length; i++) {
        if (parseInt(hash[i], 16) >= 8) {
            ret += address[i].toUpperCase()
        } else {
            ret += address[i]
        }
    }

    return ret
}

export function buildLogsObject(logs: any[], blHash: string, blNumber: string, txHash: string, txIndex: string): EthLog[] {
    const _logs: EthLog[] = [];
    if (logs) {
        if(isHexPrefixed(txHash) === false) {
            txHash = '0x' + txHash;
        }
        let counter = 0;
        for (const log of logs) {
            _logs.push({
                address: toChecksumAddress(log.address),
                blockHash: blHash,
                blockNumber: blNumber,
                data: "0x" + log.data,
                logIndex: numToHex(counter),
                removed: false,
                topics: log.topics.map(t => '0x' + t.padStart(64, '0')),
                transactionHash: txHash,
                transactionIndex: txIndex
            });
            counter++;
        }
    }
    return _logs;
}

export function parseRevertReason(revertOutput) {
    if (!revertOutput || revertOutput.length < 138) {
        return '';
    }

    let reason = '';
    let trimmedOutput = revertOutput.substr(138);
    for (let i = 0; i < trimmedOutput.length; i += 2) {
        reason += String.fromCharCode(parseInt(trimmedOutput.substr(i, 2), 16));
    }
    return reason;
}

export function parsePanicReason(revertOutput) {
    let trimmedOutput = revertOutput.slice(-2)
    let reason;

    switch (trimmedOutput) {
        case "01":
            reason = "If you call assert with an argument that evaluates to false.";
            break;
        case "11":
            reason = "If an arithmetic operation results in underflow or overflow outside of an unchecked { ... } block.";
            break;
        case "12":
            reason = "If you divide or modulo by zero (e.g. 5 / 0 or 23 % 0).";
            break;
        case "21":
            reason = "If you convert a value that is too big or negative into an enum type.";
            break;
        case "31":
            reason = "If you call .pop() on an empty array.";
            break;
        case "32":
            reason = "If you access an array, bytesN or an array slice at an out-of-bounds or negative index (i.e. x[i] where i >= x.length or i < 0).";
            break;
        case "41":
            reason = "If you allocate too much memory or create an array that is too large.";
            break;
        case "51":
            reason = "If you call a zero-initialized variable of internal function type.";
            break;
        default:
            reason = "Default panic message";
    }
    return reason;
}

export function toOpname(opcode) {
    switch (opcode) {
        case "f0":
            return "create";
        case "f1":
            return "call";
        case "f4":
            return "delegatecall";
        case "f5":
            return "create2";
        case "fa":
            return "staticcall";
        case "ff":
            return "selfdestruct";
        default:
            return "unkown";
    }
}

export function makeLogObject(rawActionDocument, log, forSubscription) {
    let trx = rawActionDocument['@raw']['hash'];
    if(!isHexPrefixed(trx)) {
        trx = '0x' + trx;
    }
    let baseLogObj = {
        address: toChecksumAddress('0x' + log.address),
        blockHash: '0x' + rawActionDocument['@raw']['block_hash'],
        blockNumber: numToHex(rawActionDocument['@raw']['block']),
        data: '0x' + log.data,
        logIndex: numToHex(log.logIndex),
        topics: log.topics.map(t => '0x' + t.padStart(64, '0')),
        transactionHash: trx,
        transactionIndex: numToHex(rawActionDocument['@raw']['trx_index'])
    }

    if (forSubscription)
        return baseLogObj;

    return Object.assign(baseLogObj, {
        removed: false,
    });
}

export function reverseHex(hex: string) {
    return hex.substring(6, 8) + hex.substring(4, 6) + hex.substring(2, 4) + hex.substring(0, 2);
}

export function logFilterMatch(log, addressFilter, topicsFilter) {
    if (addressFilter) {
        let thisAddr = removeZeroHexFromFilter(log.address.toLowerCase(), true);
        addressFilter = removeZeroHexFromFilter(addressFilter, true);
        if (Array.isArray(addressFilter) && !addressFilter.includes(thisAddr)) {
            return false;
        }

        if (!Array.isArray(addressFilter) && thisAddr != addressFilter) {
            return false;
        }
    }

    if (topicsFilter) {
        if (!hasTopics(log.topics, topicsFilter)) {
            return false;
        }
    }

    return true;
}

export function addHexPrefix(str: string): string {
    if (typeof str !== 'string') {
        return str
    }

    return isHexPrefixed(str) ? str : '0x' + str
}

export function isHexPrefixed(str: string): boolean {
    if (typeof str !== 'string') {
        throw new Error(`[isHexPrefixed] input must be type 'string', received type ${typeof str}`)
    }

    return str[0] === '0' && str[1] === 'x'
}

export function leftPadZerosEvenBytes(value) {
    let removed = value.replace(/^0x/, '');
    return removed.length % 2 === 0 ? `0x${removed}` : `0x0${removed}`
}

export function removeLeftZeros(value, zeroXPrefix=true) {
    let removed =`${value.replace(/^0x/, '').replace(/^(0)*/, '')}`;
    if (removed === '')
        removed = '0';

    return zeroXPrefix ? `0x${removed}` : removed;
}

export function removeZeroHexFromFilter(filter, trimLeftZeros=false) {
    if (!filter)
        return filter;

    if (Array.isArray(filter)) {
        return filter.map((f) => {
            if (!f)
                return f;

            let noPrefix = f.replace(/^0x/, '').toLowerCase();
            let val =  trimLeftZeros ? noPrefix.replace(/^(00)+/, '') : noPrefix;
            return val;
        })
    }

    let noPrefix = filter.replace(/^0x/, '').toLowerCase();
    let val = trimLeftZeros ? noPrefix.replace(/^(00)+/, '') : noPrefix;
    return val;
}

export function hasTopics(topics: string[], topicsFilter: string[]) {
    const topicsFiltered = [];
    topics = removeZeroHexFromFilter(topics, true);
    topicsFilter = topicsFilter.map(t => {
        return removeZeroHexFromFilter(t, true);
    })
    for (const [index, filterTopic] of topicsFilter.entries()) {
        const topic = topics[index];
        const isFilterArray = Array.isArray(filterTopic);
        if (filterTopic === null) {
            topicsFiltered.push(true);
        } else if (topic === filterTopic) {
            topicsFiltered.push(true);
        } else if (isFilterArray && filterTopic.includes(topic)) {
            topicsFiltered.push(true);
        } else {
            topicsFiltered.push(false);
        }
    }
    return topicsFiltered.every(t => t === true);
}
