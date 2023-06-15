// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.7;

import "../interfaces/IDecapacitor.sol";
import "../libraries/RescueFundsLib.sol";
import "../utils/AccessControl.sol";
import {RESCUE_ROLE} from "../utils/AccessRoles.sol";

/**
 * @title HashChainDecapacitor
 * @notice  This is an experimental contract and have known bugs
 * @notice A contract that verifies whether a message is part of a hash chain or not.
 * @dev This contract implements the `IDecapacitor` interface.
 */
contract HashChainDecapacitor is IDecapacitor, AccessControl {
    /**
     * @notice Initializes the HashChainDecapacitor contract with the owner's address.
     * @param owner_ The address of the contract owner.
     */
    constructor(address owner_) AccessControl(owner_) {
        _grantRole(RESCUE_ROLE, owner_);
    }

    /**
     * @notice Verifies whether a message is included in the given hash chain.
     * @param root_ The root of the hash chain.
     * @param packedMessage_ The packed message whose inclusion in the hash chain needs to be verified.
     * @param proof_ The proof for the inclusion of the packed message in the hash chain.
     * @return True if the packed message is included in the hash chain and the provided root is the calculated root; otherwise, false.
     */
    function verifyMessageInclusion(
        bytes32 root_,
        bytes32 packedMessage_,
        bytes calldata proof_
    ) external pure override returns (bool) {
        bytes32[] memory chain = abi.decode(proof_, (bytes32[]));
        bytes32 generatedRoot;
        bool isIncluded;
        /// @solidity memory-safe-assembly
        assembly {
            if mload(chain) {
                // Initialize `offset` to the offset of `chain` elements in memory.
                let offset := add(chain, 0x20)
                // Left shift by 5 is equivalent to multiplying by 0x20.
                // finding the position of the end of the array by adding chain's length's size to offset.
                let end := add(offset, shl(5, mload(chain)))
                // Iterate over chain elements to compute root hash.
                for {} 1 {} {
                    // Store elements to hash contiguously in scratch space.
                    // Scratch space is 64 bytes (0x00 - 0x3f) and both elements are 32 bytes.
                    mstore(0x00, generatedRoot)
                    mstore(0x20, mload(offset))
                    // generatedRoot = keccak256(abi.encode(generatedRoot, chain[i]));
                    generatedRoot := keccak256(0x00, 0x40)
                    // if (chain[i] == packedMessage_) isIncluded = true;
                    if eq(mload(offset), packedMessage_) {
                        isIncluded := true
                    }
                    // i++
                    offset := add(offset, 0x20)
                    // i < len
                    if iszero(lt(offset, end)) { break }
                }
            }
        }
        return root_ == generatedRoot && isIncluded;
    }

    /**
     * @notice Rescues funds from a contract that has lost access to them.
     * @param token_ The address of the token contract.
     * @param userAddress_ The address of the user who lost access to the funds.
     * @param amount_ The amount of tokens to be rescued.
     */
    function rescueFunds(
        address token_,
        address userAddress_,
        uint256 amount_
    ) external onlyRole(RESCUE_ROLE) {
        RescueFundsLib.rescueFunds(token_, userAddress_, amount_);
    }
}
