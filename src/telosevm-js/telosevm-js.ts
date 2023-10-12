import * as ethTx from '@ethereumjs/tx'
const { Transaction } = ethTx
import Common from '@ethereumjs/common'
import { privateToAddress } from 'ethereumjs-util'
import { TelosApi } from './telos'
export { TransactionVars } from './telos'
import {
  ETH_CHAIN,
  FORK,
  DEFAULT_GAS_LIMIT,
  DEFAULT_CHAIN_ID,
  DEFAULT_VALUE,
} from './constants'

export class TelosEvmApi {
  chainId: any
  chainConfig: any
  eth: any
  ethContract: string | undefined
  telos: TelosApi
  debug: boolean

  constructor({
    telosPrivateKey,
    signingAccount,
    signingPermission,
    nodeos_read,
    nodeos_write,
    telosContract,
    ethContract,
    evmChainId = DEFAULT_CHAIN_ID,
    antelopeChainId
  }: {
    telosPrivateKey: string
    signingAccount: string
    signingPermission?: string
    nodeos_read: string
    nodeos_write: string
    telosContract: string
    ethContract?: string
    evmChainId: number
    antelopeChainId: string
  }) {
    this.telos = new TelosApi({
      telosPrivateKey,
      signingAccount,
      signingPermission,
      nodeos_read,
      nodeos_write,
      telosContract,
      evmChainId,
      antelopeChainId
    })
    this.chainId = evmChainId
    this.ethContract = ethContract
    this.chainConfig = Common.forCustomChain(ETH_CHAIN, { chainId: evmChainId }, FORK)
    this.debug = false
  }

  setDebug(b: boolean) {
    this.debug = b
    this.telos.setDebug(b)
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
  }: {
    sender?: string
    data?: string
    gasLimit?: string | Buffer
    value?: number | Buffer
    to?: string
  }) {
    const nonce = await this.telos.getNonce(sender)
    const gasPrice = await this.telos.getGasPrice()
    const txData = {
      nonce,
      gasPrice: `0x${gasPrice.toString(16)}`,
      gasLimit:
        gasLimit !== undefined
          ? `0x${(gasLimit as any).toString(16)}`
          : DEFAULT_GAS_LIMIT,
      value:
        value !== undefined
          ? `0x${(value as any).toString(16)}`
          : DEFAULT_VALUE,
      to,
      data
    }

    const tx = new Transaction(txData, { common: this.chainConfig })

    return tx.serialize().toString('hex')
  }
}
