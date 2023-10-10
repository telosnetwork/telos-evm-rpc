import { ethers } from "ethers";

//const rpc = 'https://testnet.telos.net/evm';
const rpc = 'http://141.193.240.11:12001/evm'
const batchSize = 30;
const signerKey = '0x87ef69a835f8cd0c44ab99b7609a20b2ca7f1c8470af4f0e5b44db927d542084';
const toAddress = '0xf79B834A37f3143F4a73fC3934eDac67fd3a01CD';
const gasLimit = 22000;
const gasPrice = ethers.utils.parseUnits('600', 'gwei');
const provider = new ethers.providers.JsonRpcProvider(rpc);
const wallet = new ethers.Wallet(signerKey);
const walletSigner = wallet.connect(provider);
const signerAddress = wallet.address;

async function test() {
    console.log(`Running with address: ${signerAddress} with balance ${ethers.utils.formatEther(await provider.getBalance(signerAddress))}`);
    const startingNonce = await provider.getTransactionCount(signerAddress, "latest");
    const promises: Promise<boolean>[] = [];
    for (let i = startingNonce; i < (startingNonce + batchSize); i++) {
        promises.push(sendTrxAndConfirm(i));
    }

    console.log(`Starting batch send`);
    const start = Date.now();
    const results = await Promise.all(promises);
    const duration = Date.now() - start;
    const failures = results.filter(result => !result);
    if (failures.length) {
        console.error(`${failures.length} failed of ${results.length} results for batch size ${batchSize}`);
        return;
    }

    console.log(`Batch of ${batchSize} send complete in ${duration}ms for a rate of ${batchSize / (duration / 1000)}trx/s`);
}

async function sendTrxAndConfirm(nonce: number): Promise<boolean> {
    console.log(`Sending for nonce: ${nonce}`);
    try {
        const result = await walletSigner.sendTransaction({
            from: signerAddress,
            to: toAddress,
            value: ethers.utils.parseEther('0.000001'),
            nonce,
            gasLimit,
            gasPrice
        });

        console.log(`Sent nonce: ${nonce}, waiting for receipt`);
        const receipt = await result.wait(1);
        console.log(`Confirmed nonce: ${nonce}, receipt: ${receipt.transactionHash}`);
        return true;
    } catch (e) {
        console.error(`Failure sending nonce ${nonce}`, e);
        return false;
    }
}

test();