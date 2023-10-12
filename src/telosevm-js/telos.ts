/*
import { Api, JsonRpc } from 'eosjs'
import { JsSignatureProvider } from 'eosjs/dist/eosjs-jssig'
import { TextEncoder, TextDecoder } from 'text-encoding'
 */
import { Account } from './interfaces'
import * as ethTx from '@ethereumjs/tx'
const { Transaction } = ethTx
import Common from '@ethereumjs/common'
import { ETH_CHAIN, FORK } from './constants'
import {APIClient, FetchProvider} from "@wharfkit/antelope"
import {Session} from "@wharfkit/session";
const {WalletPluginPrivateKey} = require('@wharfkit/wallet-plugin-privatekey')

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
export class TelosApi {
  //signatureProvider: any
  signingPermission: string
  //rpc: any
  //api: any
  antelopeSession: Session
  antelopeApi: APIClient
  telosContract: string
  chainConfig: any
  debug: boolean

  constructor({
    telosPrivateKey,
    signingAccount,
    signingPermission,
    nodeos_read,
    nodeos_write,
    telosContract,
    evmChainId,
    antelopeChainId
  }: {
    telosPrivateKey: string
    signingAccount?: string
    signingPermission?: string
    nodeos_read: string
    nodeos_write: string
    telosContract: string
    evmChainId: any
    antelopeChainId: string
  }) {
    this.antelopeApi = new APIClient({
      provider: new FetchProvider(nodeos_read)
    })
    //this.signatureProvider = new JsSignatureProvider(this.telosPrivateKeys)
    this.signingPermission = signingPermission || 'active'
    this.antelopeSession = new Session({
      actor: signingAccount,
      permission: signingPermission,
      chain: {
        id: antelopeChainId,
        url: nodeos_write
      },
      walletPlugin: new WalletPluginPrivateKey(telosPrivateKey)
    })
    /*
    this.rpc = new JsonRpc(endpoint, { fetch: fetch as any })
    this.api = new Api({
      rpc: this.rpc,
      signatureProvider: this.signatureProvider,
      textEncoder: new TextEncoder() as any,
      textDecoder: new TextDecoder() as any
    })
     */
    this.chainConfig = Common.forCustomChain(ETH_CHAIN, { chainId: evmChainId }, FORK)
    this.telosContract = telosContract
    this.debug = false
  }

  setDebug(b: boolean) {
    this.debug = b
  }

  throwError(error: any, defaultMessage: string) {
    let errorMessage = defaultMessage
    const assertionPrefix = `assertion failure with message:`;
    if (error.details[0].message.startsWith(assertionPrefix))
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
   * @param {any[]} actionsFull Telos actions
   * @param {Api} api An optional Api instance to use for sending the transaction
   * @returns {Promise<any>} EVM receipt and Telos receipt
   */
  async transact(actions: any[], trxVars?: TransactionVars) {
    try {
      let trx: any = {
        actions
      }

      let trxOpts: any = {
        broadcast: true,
        sign: true
      }

      if (trxVars) {
        trx.ref_block_num = trxVars.ref_block_num
        trx.ref_block_prefix = trxVars.ref_block_prefix
        trx.expiration = trxVars.expiration
      } else {
        trxOpts.blocksBehind = 3
        trxOpts.expireSeconds = 3000
      }

      const result = await this.antelopeSession.transact(
        trx, trxOpts
      )
      if (this.debug) {
        try {
          result.response.processed.action_traces.forEach((trace: any) => {
            console.log(trace.console)
          })
        } catch (e: any) {
          console.error(
            `Failed to log result: ${e.message}\nResult:${JSON.stringify(result)}`
          )
        }
      }
      return result.response
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
    trxVars
  }: {
    account: string
    tx: string
    sender?: string
    ram_payer?: string
    trxVars?: TransactionVars
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
    ], trxVars)

    if (this.debug) {
      console.log(`In raw, console is: ${response.telos.processed.action_traces[0].console}`)
    }

    let trx = Transaction.fromSerializedTx(Buffer.from(tx, 'hex'), {
      common: this.chainConfig
    })

    response.eth = {
      transactionHash: trx.hash().toString('hex'),
      transaction: trx,
      from: sender
    }

    /*
    try {
      response.eth = JSON.parse(
        response.telos.processed.action_traces[0].console
      )
    } catch (e) {
      response.eth = ''
      console.log(
        'Could not parse',
        response.telos.processed.action_traces[0].console
      )
    }

    if (response.eth === '') {
      console.warn('Warning: This node may have console printing disabled')
    }

    */

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
    trxVars
  }: {
    account: string
    tx: string
    sender?: string
    ram_payer?: string
    trxVars?: TransactionVars
  }) {
    if (tx && tx.startsWith('0x')) tx = tx.substring(2)
    if (sender && sender.startsWith('0x')) sender = sender.substring(2)
    if (!ram_payer) ram_payer = account

    try {
      await this.transact([
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
      ], trxVars)
    } catch (e: any) {
      const error = e.json.error
      if (error.code !== 3050003) {
        throw new Error('This node does not have console printing enabled')
      }
      // TODO: there isn't always pending console output, so accessing message.match(/(0[xX][0-9a-fA-F]*)$/)[0] will fail, the real error message is somewhere else in the error, see example:
      const message = error.details[1].message
      const result = message.match(/(0[xX][0-9a-fA-F]*)$/)

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

      if (receipt.status === 0) {
        let e = new GasEstimateError("Gas estimation transaction failure");
        e.receipt = receipt;
        throw e;
      }

      if (result) {
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
      this.throwError(error, defaultMessage)
    }
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
    trxVars
  }: {
    account: string
    tx: string
    sender?: string
    ram_payer?: string
    trxVars?: TransactionVars
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
      ], trxVars)
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
    return await this.antelopeApi.v1.chain.get_table_rows(params)
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
      return undefined
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

}
