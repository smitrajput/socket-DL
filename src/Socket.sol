// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.7;

import "./interfaces/IAccumulator.sol";
import "./interfaces/IDeaccumulator.sol";
import "./interfaces/IVerifier.sol";
import "./interfaces/IPlug.sol";
import "./interfaces/IHasher.sol";
import "./utils/ReentrancyGuard.sol";

import "./SocketConfig.sol";

contract Socket is SocketConfig, ReentrancyGuard {
    enum MessageStatus {
        NOT_EXECUTED,
        SUCCESS,
        FAILED
    }

    uint256 private immutable _chainId;

    bytes32 private constant EXECUTOR_ROLE = keccak256("EXECUTOR");

    // localPlug => remoteChainId => nonce
    mapping(address => mapping(uint256 => uint256)) private _nonces;

    // msgId => executorAddress
    mapping(uint256 => address) private executor;

    // msgId => message status
    mapping(uint256 => MessageStatus) private _messagesStatus;

    IHasher public hasher;
    IVault public override vault;

    /**
     * @param chainId_ current chain id (should not be more than uint16)
     */
    constructor(
        uint16 chainId_,
        address hasher_,
        address vault_
    ) {
        _setHasher(hasher_);
        _setVault(vault_);

        _chainId = chainId_;
    }

    function setHasher(address hasher_) external onlyOwner {
        _setHasher(hasher_);
    }

    function setVault(address vault_) external onlyOwner {
        _setVault(vault_);
    }

    /**
     * @notice registers a message
     * @dev Packs the message and includes it in a packet with accumulator
     * @param remoteChainId_ the remote chain id
     * @param msgGasLimit_ the gas limit needed to execute the payload on remote
     * @param payload_ the data which is needed by plug at inbound call on remote
     */
    function outbound(
        uint256 remoteChainId_,
        uint256 msgGasLimit_,
        bytes calldata payload_
    ) external payable override {
        PlugConfig memory plugConfig = plugConfigs[msg.sender][remoteChainId_];
        uint256 nonce = _nonces[msg.sender][remoteChainId_]++;

        // Packs the local plug, local chain id, remote chain id and nonce
        // msgId(256) = localPlug(160) | localChainId(16) | remoteChainId(16) | nonce(64)
        uint256 msgId = (uint256(uint160(msg.sender)) << 96) |
            (uint256(uint16(_chainId)) << 80) |
            (uint256(uint16(remoteChainId_)) << 64) |
            uint256(uint64(nonce));

        vault.deductFee{value: msg.value}(
            remoteChainId_,
            plugConfig.integrationType
        );

        bytes32 packedMessage = hasher.packMessage(
            _chainId,
            msg.sender,
            remoteChainId_,
            plugConfig.remotePlug,
            msgId,
            msgGasLimit_,
            payload_
        );

        IAccumulator(plugConfig.accum).addPackedMessage(packedMessage);
        emit MessageTransmitted(
            _chainId,
            msg.sender,
            remoteChainId_,
            plugConfig.remotePlug,
            msgId,
            msgGasLimit_,
            payload_
        );
    }

    /**
     * @notice executes a message
     * @param msgGasLimit gas limit needed to execute the inbound at remote
     * @param msgId message id packed with local plug, local chainId, remote chainId and nonce
     * @param localPlug remote plug address
     * @param payload the data which is needed by plug at inbound call on remote
     * @param verifyParams_ the details needed for message verification
     */
    function execute(
        uint256 msgGasLimit,
        uint256 msgId,
        address localPlug,
        bytes calldata payload,
        ISocket.VerificationParams calldata verifyParams_
    ) external override nonReentrant {
        if (!_hasRole(EXECUTOR_ROLE, msg.sender)) revert ExecutorNotFound();
        if (executor[msgId] != address(0)) revert MessageAlreadyExecuted();
        executor[msgId] = msg.sender;

        PlugConfig memory plugConfig = plugConfigs[localPlug][
            verifyParams_.remoteChainId
        ];
        bytes32 packedMessage = hasher.packMessage(
            verifyParams_.remoteChainId,
            plugConfig.remotePlug,
            _chainId,
            localPlug,
            msgId,
            msgGasLimit,
            payload
        );

        _verify(packedMessage, plugConfig, verifyParams_);
        _execute(localPlug, msgGasLimit, msgId, payload);
    }

    function _verify(
        bytes32 packedMessage,
        PlugConfig memory plugConfig,
        ISocket.VerificationParams calldata verifyParams_
    ) internal view {
        (bool isVerified, bytes32 root) = IVerifier(plugConfig.verifier)
            .verifyPacket(
                verifyParams_.accum,
                verifyParams_.remoteChainId,
                verifyParams_.packetId,
                plugConfig.integrationType
            );

        if (!isVerified) revert VerificationFailed();

        if (
            !IDeaccumulator(plugConfig.deaccum).verifyMessageInclusion(
                root,
                packedMessage,
                verifyParams_.deaccumProof
            )
        ) revert InvalidProof();
    }

    function _execute(
        address localPlug,
        uint256 msgGasLimit,
        uint256 msgId,
        bytes calldata payload
    ) internal {
        try IPlug(localPlug).inbound{gas: msgGasLimit}(payload) {
            _messagesStatus[msgId] = MessageStatus.SUCCESS;
            emit ExecutionSuccess(msgId);
        } catch Error(string memory reason) {
            // catch failing revert() and require()
            _messagesStatus[msgId] = MessageStatus.FAILED;
            emit ExecutionFailed(msgId, reason);
        } catch (bytes memory reason) {
            // catch failing assert()
            _messagesStatus[msgId] = MessageStatus.FAILED;
            emit ExecutionFailedBytes(msgId, reason);
        }
    }

    /**
     * @notice adds an executor
     * @param executor_ executor address
     */
    function grantExecutorRole(address executor_) external onlyOwner {
        _grantRole(EXECUTOR_ROLE, executor_);
    }

    /**
     * @notice removes an executor from `remoteChainId_` chain list
     * @param executor_ executor address
     */
    function revokeExecutorRole(address executor_) external onlyOwner {
        _revokeRole(EXECUTOR_ROLE, executor_);
    }

    function _setHasher(address hasher_) private {
        hasher = IHasher(hasher_);
    }

    function _setVault(address vault_) private {
        vault = IVault(vault_);
    }

    function chainId() external view returns (uint256) {
        return _chainId;
    }

    function getMessageStatus(uint256 msgId_)
        external
        view
        returns (MessageStatus)
    {
        return _messagesStatus[msgId_];
    }
}
