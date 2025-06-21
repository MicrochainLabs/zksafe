import { zeroAddress, parseEther, encodeFunctionData, toHex, Account, toBytes, recoverAddress, recoverPublicKey, Hex, createWalletClient, http, WalletClient, checksumAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { formatEther } from 'viem';
import Safe, { HexAddress } from '@safe-global/protocol-kit';
import { SafeAccountConfig } from '@safe-global/protocol-kit';
import { SafeTransactionData, SafeSignature } from '@safe-global/types-kit';
import assert from 'assert';
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { vars } from "hardhat/config";

import circuit from '../noir/circuits/target/circuits.json';
import { Noir } from '@noir-lang/noir_js';
import { UltraHonkBackend } from '@aztec/bb.js';

import ZkSafeModule from "../ignition/modules/zkSafe";
import { IMT } from "@zk-kit/imt";
import { Hex, poseidon } from "@iden3/js-crypto";

/// Extract x and y coordinates from a serialized ECDSA public key.
export function extractCoordinates(serializedPubKey: string): { x: number[], y: number[] } {
    // Ensure the key starts with '0x04' which is typical for an uncompressed key.
    if (!serializedPubKey.startsWith('0x04')) {
        throw new Error('The public key does not appear to be in uncompressed format.');
    }

    // The next 64 characters after the '0x04' are the x-coordinate.
    let xHex = serializedPubKey.slice(4, 68);

    // The following 64 characters are the y-coordinate.
    let yHex = serializedPubKey.slice(68, 132);

    // Convert the hex string to a byte array.
    let xBytes = Array.from(Buffer.from(xHex, 'hex'));
    let yBytes = Array.from(Buffer.from(yHex, 'hex'));
    return { x: xBytes, y: yBytes };
}

export function extractRSFromSignature(signatureHex: string): number[] {
    if (signatureHex.length !== 132 || !signatureHex.startsWith('0x')) {
        throw new Error('Signature should be a 132-character hex string starting with 0x.');
    }
    return Array.from(Buffer.from(signatureHex.slice(2, 130), 'hex'));
}

export function addressToArray(address: string): number[] {
    if (address.length !== 42 || !address.startsWith('0x')) {
        throw new Error('Address should be a 40-character hex string starting with 0x.');
    }
    return Array.from(toBytes(address));
}

export function padArray(arr: any[], length: number, fill: any = 0) {
    return arr.concat(Array(length - arr.length).fill(fill));
}

function ensureHexPrefix(value: string): `0x${string}` {
    return value.startsWith("0x") ? value as `0x${string}` : `0x${value}`;
}

export async function zksend(hre: any, safeAddr: string, to: string, value: string, data: string, proof: string) {
    // Get wallet client
    const pk = ensureHexPrefix(vars.get("DEPLOYER_PRIVATE_KEY") as string);
    const account = privateKeyToAccount(pk);
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);
    const publicClient = await hre.viem.getPublicClient();

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const safeAddress = await safe.getAddress();
    console.log("connected to safe ", safeAddress);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    // Find ZkSafeModule
    const modules = await safe.getModules();
    let zkSafeModule = null;
    for (const moduleAddress of modules) {
        console.log("Checking module: ", moduleAddress);
        try {
            const module = await hre.viem.getContractAt("ZkSafeModule", moduleAddress);
            const version = await module.read.zkSafeModuleVersion();
            console.log("ZkSafe version: ", version);
            zkSafeModule = module;
            break;
        } catch (e) {
            console.log("Not a ZkSafe module", e);
        }
    }
    if (!zkSafeModule) {
        throw new Error(`ZkSafeModule not found on Safe ${safeAddress}`);
    }

    // Send transaction
    const txn = await zkSafeModule.write.sendZkSafeTransaction([
        safeAddress,
        {
            to,
            value: BigInt(value),
            data,
            operation: 0
        },
        proof
    ]);

    console.log("Transaction hash: ", txn);
    const receipt = await publicClient.waitForTransactionReceipt({ hash: txn });
    console.log("Transaction result: ", receipt);
}

export async function proveTransactionSignatures(hre: HardhatRuntimeEnvironment, safe: Safe, signatures: Hex[], txHash: Hex, zkSafeModulePrivateOwners: string[], ownersAddressesFormat: number, moduleOwnersRoot: Hex, muduleOwnersThreshold: Hex) {
        const { noir, backend } = await hre.noir.getCircuit("circuits");
        console.log("noir backend initialized");

        const nil_pubkey = {
            x: Array.from(toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")),
            y: Array.from(toBytes("0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"))
        };
        // Our Nil signature is a signature with r and s set to the generator point.
        const nil_signature = Array.from(
            toBytes("0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"));
        const zero_address = new Array(20).fill(0);

        // Sort signatures by address - this is how the Safe contract does it.
        const sortedSignatures = await Promise.all(signatures.map(async (sig) => {
            const addr = await recoverAddress({hash: txHash, signature: sig});
            return { sig, addr };
        }));
        sortedSignatures.sort((a, b) => a.addr.localeCompare(b.addr));
        const sortedSigs = sortedSignatures.map(s => s.sig);

        const modulePrivateOwnersTree = new IMT(poseidon.hash, 4, 0, 2)
        for (var privateOwner of zkSafeModulePrivateOwners) {
            /*0: Normal address
            1: Poseidon Hash address*/
            if(ownersAddressesFormat == 0)
                modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner)]))
            else if (ownersAddressesFormat == 1) 
                modulePrivateOwnersTree.insert(BigInt(privateOwner))
            else
                throw new Error("Invalid owner addresses format variable value (0: Normal address) or (1: Poseidon Hash address)");
        }
        if(moduleOwnersRoot != toHex(modulePrivateOwnersTree.root)){
            throw new Error("Invalid owners");
        }
        const ownersIndicesProof: number[] = []
        const ownersPathsProof: any[][] = []
            for (var signature of sortedSigs) {
            const recoveredAddress = await recoverAddress({hash: txHash, signature: signature});
            const index= await modulePrivateOwnersTree.indexOf(poseidon.hash([BigInt(recoveredAddress)]));
            const addressProof= await modulePrivateOwnersTree.createProof(index);
            addressProof.siblings = addressProof.siblings.map((s) => s[0])
            await ownersIndicesProof.push(Number("0b" + await addressProof.pathIndices.join("")))
            await ownersPathsProof.push(addressProof.siblings)
        }

        const input = {
            threshold: muduleOwnersThreshold,
            signers: padArray(await Promise.all(sortedSigs.map(async (sig) => {
                const pubKey = await recoverPublicKey({
                    hash: txHash as `0x${string}`,
                    signature: sig
                });
                const recoveredAddress = await recoverAddress({hash: txHash, signature: signature});
                return extractCoordinates(pubKey);
            })), 10, nil_pubkey),
            signatures: padArray(sortedSigs.map(sig => extractRSFromSignature(sig)), 10, nil_signature),
            txn_hash: Array.from(toBytes(txHash as `0x${string}`)),
            owners_root:  moduleOwnersRoot,
            indices: padArray(ownersIndicesProof.map(indice => toHex(indice)), 10, "0x0"),
            siblings: padArray(ownersPathsProof.map(paths => paths.map(path => toHex(path))), 10, ["0x0", "0x0", "0x0", "0x0"])
        };
       
        // Generate witness first
        const { witness } = await noir.execute(input);

        // Use backend to generate proof from witness
        const proof = await backend.generateProof(witness, { keccak: true });

        // Verify proof
        const verification = await backend.verifyProof(proof, { keccak: true });
        assert(verification, "Verification failed");
        console.log("verification in JS succeeded");
        return proof;
}


export async function prove(hre: HardhatRuntimeEnvironment, safeAddr: string, txHash: string, signatures_: string, zkSafeModulePrivateOwners: string[], ownersAddressesFormat: number) {
    // Initialize Safe - we need it to prepare the witness (owners/threeshold) from onchain data.
    const safe = await Safe.init({
        provider: hre.network.config.url,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const signatures = signatures_.split(",").map(sig => sig.trim()).filter(sig => {
        if (!sig.startsWith("0x")) {
            throw new Error("Invalid signature format (must start with 0x)");
        }
        return true;
    });
    
    
    // Find ZkSafeModule
    const modules = await safe.getModules();
    let zkSafeModule = null;
    for (const moduleAddress of modules) {
        console.log("Checking module: ", moduleAddress);
        try {
            const module = await hre.viem.getContractAt("ZkSafeModule", moduleAddress);
            const version = await module.read.zkSafeModuleVersion();
            console.log("ZkSafe version: ", version);
            zkSafeModule = module;
            break;
        } catch (e) {
            console.log("Not a ZkSafe module", e);
        }
    }
    if (!zkSafeModule) {
        throw new Error(`ZkSafeModule not found on Safe ${address}`);
    }
    
    const safeModuleConfig = await zkSafeModule.read.safeToConfig([address])

    const proof = await proveTransactionSignatures(hre, safe, signatures as Hex[], txHash as Hex, zkSafeModulePrivateOwners, ownersAddressesFormat, safeModuleConfig[0], toHex(safeModuleConfig[1]));
    console.log("Proof: ", toHex(proof.proof));
}

export async function sign(hre: HardhatRuntimeEnvironment, safeAddr: string, to: string, value: string, data: string) {
    // Get wallet client
    const pk = vars.get("SAFE_OWNER_PRIVATE_KEY") as string;
    const publicClient = await hre.viem.getPublicClient();
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const mywalletAddress = account.address;
    console.log("My wallet address: ", mywalletAddress);

    // Initialize Safe
    const safe = await Safe.init({
        provider: hre.network.config.url,
        signer: pk,
        safeAddress: safeAddr
    });

    const version = await safe.getContractVersion();
    const threshold = await safe.getThreshold();
    const owners = await safe.getOwners();
    const address = await safe.getAddress();
    console.log("connected to safe ", address);
    console.log("  version: ", version);
    console.log("  owners: ", owners);
    console.log("  threshold: ", threshold);
    console.log("  nonce: ", await safe.getNonce());
    console.log("  chainId: ", await safe.getChainId());
    console.log("  balance: ", formatEther(await safe.getBalance()));

    const safeTransactionData: SafeTransactionData = {
        to,
        value,
        data,
        operation: 0,
        // default fields below
        safeTxGas: "0x0",
        baseGas: "0x0",
        gasPrice: "0x0",
        gasToken: zeroAddress,
        refundReceiver: zeroAddress,
        nonce: await safe.getNonce(),
    };

    console.log("transaction", safeTransactionData);
    const transaction = await safe.createTransaction({ transactions: [safeTransactionData] });
    const txHash = await safe.getTransactionHash(transaction);
    console.log("txHash", txHash);

    // Sign the transaction using the Safe instance
    /*const signedTransaction = await safe.signTransaction(transaction);
    const safeSig = signedTransaction.getSignature(mywalletAddress)!;
    console.log("Signature: ", safeSig.data);*/
    const safeSig = await safe.signTypedData(transaction);
    console.log("Signature: ", safeSig.data);
}

export async function createZkSafe(hre: HardhatRuntimeEnvironment, owners: string[], threshold: number, zkSafeModulePrivateOwners: string[], zkSafeModuleThreshold: number) {
    // Get wallet client
    const pk = vars.get("DEPLOYER_PRIVATE_KEY") as string;
    const account = privateKeyToAccount(ensureHexPrefix(pk));
    const walletClient: WalletClient = createWalletClient({
        account,
        transport: http(hre.network.config.url)
    });
    const publicClient = await hre.viem.getPublicClient();
    const mywalletAddress = walletClient.account!.address;
    console.log("My wallet address: ", mywalletAddress);

    const result = await hre.ignition.deploy(ZkSafeModule);
    const zkSafeModule = result.zkSafeModule;

    console.log("zkSafeModule: ", zkSafeModule.address);

    //@ts-ignore
    const modulePrivateOwnersTree = new IMT(poseidon.hash, 4, 0, 2)
    for (var privateOwner of zkSafeModulePrivateOwners) {
        modulePrivateOwnersTree.insert(poseidon.hash([BigInt(privateOwner)]))
    }
    // Enable module
    const calldata = encodeFunctionData({
        abi: [{
            "inputs": [
                {
                "internalType": "bytes32",
                "name": "ownersRoot",
                "type": "bytes32"
                },
                {
                "internalType": "uint256",
                "name": "threshold",
                "type": "uint256"
                }
            ],
            "name": "enableModule",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        }],
        functionName: 'enableModule',
        args: [toHex(modulePrivateOwnersTree.root), BigInt(zkSafeModuleThreshold)]
    });

    const safe = await Safe.init({
        provider: walletClient.transport,
        predictedSafe: {
            safeAccountConfig: {
                owners,
                threshold: threshold,
                to: zkSafeModule.address,
                data: calldata,
            }
        },
    });

    const safeAddress = await safe.getAddress() as `0x${string}`;
    const deploymentTransaction = await safe.createSafeDeploymentTransaction();

    const transactionHash = await walletClient.sendTransaction({
        account: walletClient.account as Account,
        chain: walletClient.chain,
        to: deploymentTransaction.to,
        value: parseEther(deploymentTransaction.value),
        data: deploymentTransaction.data as `0x${string}`,
    });

    const transactionReceipt = await publicClient.waitForTransactionReceipt({
        hash: transactionHash
    });

    if (transactionReceipt.status != "success") {
        throw new Error("Safe failed to deploy.")
    }

    console.log("Created zkSafe at address: ", safeAddress);
    console.log("Private owners addresses: ", modulePrivateOwnersTree.leaves);
}
