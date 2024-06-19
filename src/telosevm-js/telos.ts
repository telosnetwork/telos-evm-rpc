import { Account } from './interfaces'
import { LegacyTransaction, Transaction, TransactionFactory } from '@ethereumjs/tx'
import { RLP } from '@ethereumjs/rlp'
import {Chain, Common, Hardfork} from '@ethereumjs/common';
import {DEFAULT_GAS_LIMIT, DEFAULT_VALUE, ETH_CHAIN, FORK} from './constants'
import {
  API,
  APIClient,
  AnyAction,
  Checksum256,
  FetchProvider,
  PrivateKey,
  Transaction as AntelopeTransaction,
  SignedTransaction,
  Action, ABI,
  UInt8,
} from "@wharfkit/antelope"

const BN = require('bn.js')

const RECEIPT_LOG_START = "RCPT{{";
const RECEIPT_LOG_END = "}}RCPT";

const transformEthAccount = (account: Account) => {
  account.address = `0x${account.address}`
  account.balance = new BN(account.balance, 16)._strip()
  let code = account.code
  if (typeof code !== 'string') {
    code = Buffer.from(account.code).toString("hex")
  }

  account.code = `0x${code.replace(/^0x/, '')}`
  return account
}
interface RevertError extends Error {
  evmCallOutput: string
}

interface GasEstimateError extends Error {
  receipt: object
}

export interface TransactionVars {
  expiration: string
  ref_block_num: number
  ref_block_prefix: number
}

class RevertError extends Error { }
class GasEstimateError extends Error { }

/**
 * Telos API used as a subset of EosEvmApi
 *
 * @param {object} args Arguments
 * @param {Array<string>} args.telosPrivateKeys Telos private keys
 * @param {Array<string>} args.endpoint Telos RPC endpoint
 * @param {Array<string>} args.telosContract Telos contract name with EVM
 */
export class TelosEvmApi {
  chainId: Checksum256
  signingPermission: string
  signingKey: PrivateKey
  writeAPI: APIClient
  readAPI: APIClient
  telosContract: string
  chainConfig: any
  debug: boolean
  private abi: ABI.Def
  private retryTrxNumBlocks: number

  constructor({
    telosPrivateKey,
    signingPermission,
    nodeosRead,
    nodeosWrite,
    telosContract,
    evmChainId,
    antelopeChainId,
    retryTrxNumBlocks
  }: {
    telosPrivateKey: string
    signingPermission?: string
    nodeosRead: string
    nodeosWrite: string
    telosContract: string
    evmChainId: any
    antelopeChainId: string
    retryTrxNumBlocks: number
  }) {
    try {
      let provider = new FetchProvider(nodeosRead);
      this.readAPI = new APIClient({
        provider: provider
      })
    } catch (e) {
      throw new Error(`Failed to create read API: ${e.message}`)
    }
    this.signingPermission = signingPermission || 'active'
    try {
      this.writeAPI =  new APIClient({
        provider: new FetchProvider(nodeosWrite)
      })
    } catch (e) {
      throw new Error(`Failed to create write API: ${e.message}`)
    }
    this.retryTrxNumBlocks = retryTrxNumBlocks
    this.chainId = Checksum256.from(antelopeChainId)
    this.signingKey = PrivateKey.from(telosPrivateKey)
    this.chainConfig = new Common({
      chain: Chain.Mainnet,
      hardfork: Hardfork.London,
      eips: [1559]
    });
    this.telosContract = telosContract
    this.debug = false
  }

  setDebug(b: boolean) {
    this.debug = b
  }

  throwError(error: any, defaultMessage: string) {
    let errorMessage = defaultMessage
    const assertionPrefix = `assertion failure with message:`;
    if (error?.details && error?.details?.length > 1 && error?.details[0]?.message?.startsWith(assertionPrefix))
      errorMessage = error.details[0].message.substring(assertionPrefix.length)

    throw new Error(errorMessage)
  }

  async getGasPrice() {
    const { rows } = await this.getTable({
      code: this.telosContract,
      scope: this.telosContract,
      table: 'config'
    })
    return rows[0].gas_price
  }

  nameToUint64(name: any) {
    let n = BigInt(0);

    let i = 0;
    for (; i < 12 && name[i]; i++) {
      n |= BigInt(this.charToSymbol(name.charCodeAt(i)) & 0x1f) << BigInt(64 - 5 * (i + 1));
    }

    if (i == 12) {
      n |= BigInt(this.charToSymbol(name.charCodeAt(i)) & 0x0f);
    }

    return n.toString();
  }

  charToSymbol(c: any) {
    if (typeof c == 'string') c = c.charCodeAt(0);

    if (c >= 'a'.charCodeAt(0) && c <= 'z'.charCodeAt(0)) {
      return c - 'a'.charCodeAt(0) + 6;
    }

    if (c >= '1'.charCodeAt(0) && c <= '5'.charCodeAt(0)) {
      return c - '1'.charCodeAt(0) + 1;
    }

    return 0;
  }

  /**
   * Bundles actions into a transaction to send to Telos Api
   *
   * @returns {Promise<any>} EVM receipt and Telos receipt
   * @param actions
   * @param trxVars
   * @param getInfoResponse
   * @param api
   */
  async transact(actions: AnyAction[], trxVars: TransactionVars, getInfoResponse: API.v1.GetInfoResponse, api: APIClient): Promise<API.v1.SendTransaction2Response> {
    try {
      let transaction: AntelopeTransaction
      const abi = await this.getAbi()
      console.log(trxVars);
      console.log(actions);

      if (trxVars) {
        transaction = AntelopeTransaction.from({
            ...trxVars,
            actions: actions.map((action) => Action.from(action, abi))
        })
      } else {
        transaction = AntelopeTransaction.from({
            ...getInfoResponse.getTransactionHeader(45),
            actions: actions.map((action) => Action.from(action, abi))
        })
      }

      const signature = this.signingKey.signDigest(transaction.signingDigest(this.chainId))

      const signed = SignedTransaction.from({
        ...transaction,
        signatures: [signature],
      })

      /* 
      const start = Date.now();
      const result = await api.v1.chain.send_transaction2(signed, {
        return_failure_trace: true,
        retry_trx: true,
        retry_trx_num_blocks: this.retryTrxNumBlocks
      })
      console.log(`send_transaction2 took ${Date.now() - start}ms`)
      */
      const result = await api.v1.chain.send_transaction(signed);
      if (this.debug) {
        try {
          result.processed.action_traces.forEach((trace: any) => {
            console.log(trace.console)
          })
        } catch (e: any) {
          console.error(
            `Failed to log result: ${e.message}\nResult:${JSON.stringify(result)}`
          )
        }
      }
      return result
    } catch (e: any) {
      if (this.debug) {
        if (e.json) {
          e.json.error.details.forEach((detail: any) => {
            console.log(detail.message)
          })
        } else {
          console.dir(e, { depth: null })
        }
      }
      throw e
    }
  }

  /**
   * Sends a ETH TX to EVM
   *
   * @param {object} args Arguments
   * @param {string} args.account Telos account to interact with EVM
   * @param {string} args.txRaw RLP encoded hex string
   * @param {string} args.sender The ETH address of an account if tx is not signed
   * @returns {Promise<EvmResponse>} EVM receipt and Telos receipt
   */
  async raw({
    account,
    tx,
    sender,
    ram_payer,
    trxVars,
    getInfoResponse
  }: {
    account: string
    tx: string
    sender?: string
    ram_payer?: string
    trxVars: TransactionVars
    getInfoResponse: API.v1.GetInfoResponse
  }) {
    if (tx && tx.startsWith('0x')) tx = tx.substring(2)
    if (sender && sender.startsWith('0x')) sender = sender.substring(2)
    if (!ram_payer) ram_payer = account

    if (this.debug) {
      console.log(`In raw, tx is: ${tx}`)
    }
    let response: any = {}
    response.telos = await this.transact([
      {
        account: this.telosContract,
        name: 'raw',
        data: {
          ram_payer,
          tx,
          estimate_gas: false,
          sender
        },
        authorization: [{ actor: account, permission: this.signingPermission }]
      }
    ], trxVars, getInfoResponse, this.writeAPI)

    if (this.debug) {
      console.log(`In raw, console is: ${response.telos.processed.action_traces[0].console}`)
    }

    let trx = TransactionFactory.fromSerializedData(Buffer.from(tx, 'hex'), {common: this.chainConfig})

    response.eth = {
      transactionHash: Array.from(trx.hash()).map(byte => byte.toString(16).padStart(2, '0')).join(''),
      transaction: trx,
      from: sender
    }

    return response
  }

  /**
   * Estimates gas used by sending transaction to the EVM
   *
   * @param {object} args Arguments
   * @param {string} args.account Telos account to interact with EVM
   * @param {string} args.txRaw RLP encoded hex string
   * @param {string} args.sender The ETH address of an account if tx is not signed
   * @param {Api} api An optional Api instance to use for sending the transaction
   * @returns {Promise<string>} Hex encoded output
   */
  // @ts-ignore
  async estimateGas({
    account,
    tx,
    sender,
    ram_payer,
    trxVars,
    getInfoResponse
  }: {
    account: string
    tx: string
    sender?: string
    ram_payer?: string
    trxVars: TransactionVars
    getInfoResponse: API.v1.GetInfoResponse
  }) {
    if (tx && tx.startsWith('0x')) tx = tx.substring(2)
    if (sender && sender.startsWith('0x')) sender = sender.substring(2)
    if (!ram_payer) ram_payer = account

    if(this.debug){
      console.log(`In estimateGas, raw tx is: ${tx}`)
    }

    try {
      const result = await this.transact([
        {
          account: this.telosContract,
          name: 'raw',
          data: {
            ram_payer,
            estimate_gas: true,
            tx,
            sender
          },
          authorization: [{ actor: account, permission: this.signingPermission }]
        }
      ], trxVars, getInfoResponse, this.writeAPI)
      const consolePrinting = this.getConsoleFromSendTransaction2Response(result)
      return this.handleEstimateGasConsole(consolePrinting)
    } catch (e: any) {
      const error = e?.response?.json?.error
      if (error?.code !== 3050003) {
        throw new Error(`Error while estimating gas: ${e.message}`)
      }
      // TODO: there isn't always pending console output, so accessing message.match(/(0[xX][0-9a-fA-F]*)$/)[0] will fail, the real error message is somewhere else in the error, see example:
      let message = error?.details[1]?.message
      message = (message === 'pending console output: ') ? error?.details[0]?.message : message;
      return this.handleEstimateGasConsole(message)
    }
  }

  // TODO: figure out how to cast response to SendTransaction2Response once except is defined on it
  getConsoleFromSendTransaction2Response(response: any) {
    if (response?.processed?.except?.code !== 3050003) {
      throw new Error(`Unable to get console output from SendTransaction2Response`)
    } else {
      return response.processed.except.stack[1].data.console
    }
  }

  handleEstimateGasConsole(message): string {
    const result = message.match(/(0[xX][0-9a-fA-F]*)$/)

    console.log(`In handleEstimateGasConsole, message is: ${message}`);
    let receiptLog = message.slice(
        message.indexOf(RECEIPT_LOG_START) + RECEIPT_LOG_START.length,
        message.indexOf(RECEIPT_LOG_END)
    );

    let receipt;
    try {
      receipt = JSON.parse(receiptLog);
    } catch (e) {
      console.log('WARNING: Failed to parse receiptLog in estimate gas');
    }

    if (receipt?.status === 0) {
      let e = new GasEstimateError("Gas estimation transaction failure");
      e.receipt = receipt;
      throw e;
    }

    if (result && result.length > 0) {
      if (!receipt.gasused) {
        return result[0]
      }

      let resultInt = parseInt(result[0], 16);
      let receiptInt = parseInt(receipt.gasused, 16);
      return receiptInt > resultInt ? `0x${receipt.gasused}` : result[0];
    } else {
      if (receipt && receipt.hasOwnProperty('gasused')) {
        return `0x${receipt.gasused}`
      }
    }

    let defaultMessage = `Server Error: Failed to estimate gas`
    this.throwError(new Error(`Could not get gas estimation from message: ${message}`), defaultMessage)
  }


  /**
   * Sends a non state modifying call to EVM
   *
   * @param {object} args Arguments
   * @param {string} args.account Telos account to interact with EVM
   * @param {string} args.txRaw RLP encoded hex string
   * @param {string} args.senderThe ETH address of an account if tx is not signed
   * @param {Api} api An optional Api instance to use for sending the transaction
   * @returns {Promise<string>} Hex encoded output
   */
  async call({
    account,
    tx,
    sender,
    ram_payer,
    trxVars,
    getInfoResponse
  }: {
    account: string
    tx: string
    sender?: string
    ram_payer?: string
    trxVars: TransactionVars
    getInfoResponse: API.v1.GetInfoResponse
  }) {
    if (tx && tx.startsWith('0x')) tx = tx.substring(2)
    if (sender && sender.startsWith('0x')) sender = sender.substring(2)
    if (!ram_payer) ram_payer = account

    try {
      await this.transact([
        {
          account: this.telosContract,
          name: 'call',
          data: {
            ram_payer,
            estimate_gas: false,
            tx,
            sender
          },
          authorization: [{ actor: account, permission: this.signingPermission }]
        }
      ], trxVars, getInfoResponse, this.writeAPI)
    } catch (e: any) {
      const error = e.json.error
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
        if (beforeResult == REVERT) {
          const err = new RevertError("Transaction reverted");
          err.evmCallOutput = result;
          throw err;
        }

        return result;
      }

      let defaultMessage = `Server Error: Error during call`
      this.throwError(error, defaultMessage)
    }
  }

  /**
   * Fetches tables based on data
   *
   * @returns {Promise<any>} Telos RPC Get tables row response
   */
  async getTable(data: any) {
    const defaultParams = {
      json: true, // Get the response as json
      code: '', // Contract that we target
      scope: '', // Account that owns the data
      table: '', // Table name
      key_type: `i64`, // Type of key
      index_position: 1, // Position of index
      lower_bound: '', // Table secondary key value
      limit: 10, // Here we limit to 10 to get ten row
      reverse: false, // Optional: Get reversed data
      show_payer: false // Optional: Show ram payer
    }
    const params = Object.assign({}, defaultParams, data)
    return await this.readAPI.v1.chain.get_table_rows(params)
  }

  /**
   * Gets the on-chain account
   *
   * @param contract The Telos contract with EVM deplyoed
   * @param address The ETH address in contract
   *
   * @returns {Promise<Account>} Account row associated with address
   * or undefined if there is no account matching the address.
   */
  async getEthAccount(address: string): Promise<Account | undefined> {
    if (!address) throw new Error('No address provided')
    if (address.startsWith('0x')) address = address.substring(2)

    address = address.toLowerCase()
    const padded = '0'.repeat(12 * 2) + address

    const { rows } = await this.getTable({
      code: this.telosContract,
      scope: this.telosContract,
      table: 'account',
      key_type: 'sha256',
      index_position: 2,
      lower_bound: padded,
      upper_bound: padded,
      limit: 1
    })

    if (rows.length && rows[0].address === address) {
      return transformEthAccount(rows[0])
    } else {
      return undefined;
    }
  }

  /**
   * Gets nonce for given address
   *
   * @param contract The Telos contract with EVM deplyoed
   * @param address The ETH address in contract
   *
   * @returns Hex-encoded nonce
   */

  /**
   * Fetches the nonce for an account
   *
   * @param address The ETH address in EVM contract
   *
   * @returns {Promise<string>} Hex encoded nonce
   */
  async getNonce(address: any) {
    if (!address) return '0x0'

    const account = await this.getEthAccount(address)

    if (!account)
        return '0x0'

    return `0x${account.nonce.toString(16)}`
  }

  /**
   * Fetches the on-chain storage value at address and key
   *
   * @param address The ETH address in EVM contract
   * @param key Storage key
   *
   * @returns {Promise<AccountState>} account state row containing key and value
   */
  async getStorageAt(address: string, key: string) {
    if (!address || !key) throw new Error('Both address and key are required')
    if (address && address.startsWith('0x')) address = address.substring(2)

    if (key && key.startsWith('0x')) key = key.substring(2)
    const paddedKey = '0'.repeat(64 - key.length) + key

    const acc = await this.getEthAccount(address)
    if (!acc)
      return '0x0';

    const { rows } = await this.getTable({
      code: this.telosContract,
      scope: acc.index,
      table: 'accountstate',
      key_type: 'sha256',
      index_position: 2,
      lower_bound: paddedKey,
      upper_bound: paddedKey,
      limit: 1
    })

    if (rows.length && rows[0].key === paddedKey) {
      return '0x' + rows[0].value
    } else {
      return '0x0'
    }
  }

  /**
   * Generates RLP encoded transaction sender parameters
   *
   * @param {object} [args={}] Arguments
   * @param {string} [args.sender]  The ETH address sending the transaction (nonce is fetched on-chain for this address)
   * @param {object} [args.data] The data in transaction
   * @param {string} [args.gasLimit]  The gas limit of the transaction
   * @param {string} [args.value]  The value in the transaction
   * @param {string} [args.to]  The ETH address to send transaction to
   *
   * @returns {Promise<string>}RLP encoded transaction
   */
  async createEthTx({
    sender,
    data,
    gasLimit,
    value,
    to,
    accessList,
    maxFeePerGas,
    maxPriorityFeePerGas
  }: {
    sender?: string
    data?: string
    gasLimit?: string | Buffer
    value?: number | Buffer
    to?: string
    accessList?: any[]
    maxFeePerGas?: string | Buffer
    maxPriorityFeePerGas?: string | Buffer
  }) {
    const nonce = await this.getNonce(sender);
    const gasPrice = await this.getGasPrice()
    const txData = {
        nonce: nonce,
        maxFeePerGas: undefined,
        maxPriorityFeePerGas: undefined,
        accessList: undefined,
        gasPrice: `0x${gasPrice.toString(16)}`,
        gasLimit:
            gasLimit !== undefined
                ? `0x${(gasLimit as any).toString(16)}`
                : DEFAULT_GAS_LIMIT,
        value:
            value !== undefined
                ? `0x${(value as any).toString(16)}`
                : DEFAULT_VALUE,
        to: to,
        data: data,
        type: undefined
    }
    if(maxFeePerGas !== undefined || maxPriorityFeePerGas !== undefined){
      txData.type = 2;
      txData.maxFeePerGas = maxFeePerGas !== undefined
          ? `0x${(maxFeePerGas as any).toString(16)}`
          : DEFAULT_VALUE
      ;
      txData.maxPriorityFeePerGas = maxPriorityFeePerGas !== undefined
          ? `0x${(maxPriorityFeePerGas as any).toString(16)}`
          : DEFAULT_VALUE
      ;
      txData.accessList = accessList || [];
    }
    console.log("Building tx with data: ", txData);
    if(txData.type === undefined){
      delete txData.type;
      const tx = LegacyTransaction.fromTxData(txData, {common: this.chainConfig});
      console.log(tx.toJSON());
      const message = RLP.encode(tx.getMessageToSign());
      return message.map(byte => (byte as any).toString(16)).join('');
    }
    const tx = TransactionFactory.fromTxData(txData, {common: this.chainConfig});
    const message = tx.getMessageToSign();
    return message.map(byte => byte.toString(16)).join('');
  }

  private async getAbi(): Promise<ABI.Def> {
    if (!this.abi) {
      const abiResponse = await this.readAPI.v1.chain.get_abi(this.telosContract)
      this.abi = abiResponse.abi
    }

    return this.abi
  }
}
