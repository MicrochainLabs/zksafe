// SPDX-License-Identifier: UNLICENSED

// Uncomment this line to use console.log
// import "hardhat/console.sol";

pragma solidity ^0.8.12;

import {UltraVerifier} from "../circuits/contract/circuits/plonk_vk.sol";
import "@safe-global/safe-contracts/contracts/common/Enum.sol";
import "@safe-global/safe-contracts/contracts/Safe.sol";


contract ZkSafeModule {

    UltraVerifier verifier;

    constructor(UltraVerifier _verifier) {
        verifier = _verifier;
    }
    
    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
    }

    function verifyZkSafeTransaction(Safe safeContract, bytes32 txHash, bytes calldata proof) public view returns (bool) {
        // Construct the input to the circuit.
        bytes32[] memory publicInputs = new bytes32[](33);

        // Threshold
        uint threshold = safeContract.getThreshold();
        require(threshold > 0, "Threshold must be greater than 0");
        require(threshold < 256, "Threshold must be less than 256");
        publicInputs[0] = bytes32(threshold);

        // Each byte of the transaction hash is given as a separate uint256 value.
        // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
        for (uint256 i = 0; i < 32; i++) {
            publicInputs[i + 1] = txHash[i];
        }
    
        address[] memory owners = safeContract.getOwners();
        require(owners.length > 0, "No owners");
        require(owners.length <= 10, "Too many owners");

        // Each Address is unpacked into 20 separate bytes, each of which is given as a separate uint256 value.
        // TODO: this is super inefficient, fix by making the circuit take compressed inputs.
        for (uint256 i = 0; i < owners.length; i++) {
            for (uint256 j = 0; j < 20; j++) {
                publicInputs[i * 20 + j + 33] = bytes32(uint256(uint8(bytes20(owners[i])[j])));
            }
        }
        for (uint256 i = owners.length; i < 10; i++) {
            for (uint256 j = 0; j < 20; j++) {
                publicInputs[i * 20 + j + 33] = bytes32(0);
            }
        }
        // Get the owners of the Safe by calling into the Safe contract.
        return verifier.verify(proof, publicInputs);

    }

    function sendZkSafeTransaction(
        Safe safeContract,
        // The Safe address to which the transaction will be sent.
        Transaction calldata transaction,
        // The proof blob.
        bytes calldata proof
    ) public payable virtual returns (bool) {
        uint256 nonce = safeContract.nonce();
        bytes32 txHash = keccak256(safeContract.encodeTransactionData(
                // Transaction info
                transaction.to,
                transaction.value,
                transaction.data,
                transaction.operation,
                0,
                // Payment info
                0,
                0, 
                address(0), 
                address(0), 
                // Signature info
                nonce
            ));

        require(verifyZkSafeTransaction(safeContract, txHash, proof), "Invalid proof");
        // All checks are successful, can execute the transaction.
        return safeContract.execTransactionFromModule(
            transaction.to, transaction.value, transaction.data, transaction.operation
        );
    }
}