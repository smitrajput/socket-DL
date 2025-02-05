// SPDX-License-Identifier: GPL-3.0-only
pragma solidity 0.8.7;

import "./ITransmitManager.sol";
import "./IExecutionManager.sol";

/**
 * @title ISocket
 * @notice An interface for a cross-chain communication contract
 * @dev This interface provides methods for transmitting and executing messages between chains,
 * connecting a plug to a remote chain and setting up switchboards for the message transmission
 * This interface also emits events for important operations such as message transmission, execution status,
 * and plug connection
 */
interface ISocket {
    /**
     * @notice A struct containing fees required for message transmission and execution
     * @param transmissionFees fees needed for transmission
     * @param switchboardFees fees needed by switchboard
     * @param executionFee fees needed for execution
     */
    struct Fees {
        uint256 transmissionFees;
        uint256 switchboardFees;
        uint256 executionFee;
    }

    /**
     * @title MessageDetails
     * @dev This struct defines the details of a message to be executed in a Decapacitor contract.
     */
    struct MessageDetails {
        // A unique identifier for the message.
        bytes32 msgId;
        // The fee to be paid for executing the message.
        uint256 executionFee;
        // The maximum amount of gas that can be used to execute the message.
        uint256 msgGasLimit;
        bytes32 extraParams;
        // The payload data to be executed in the message.
        bytes payload;
        // The proof data required by the Decapacitor contract to verify the message's authenticity.
        bytes decapacitorProof;
    }

    /**
     * @notice emits the message details when a new message arrives at outbound
     * @param localChainSlug local chain slug
     * @param localPlug local plug address
     * @param dstChainSlug remote chain slug
     * @param dstPlug remote plug address
     * @param msgId message id packed with remoteChainSlug and nonce
     * @param msgGasLimit gas limit needed to execute the inbound at remote
     * @param payload the data which will be used by inbound at remote
     */
    event MessageOutbound(
        uint32 localChainSlug,
        address localPlug,
        uint32 dstChainSlug,
        address dstPlug,
        bytes32 msgId,
        uint256 msgGasLimit,
        bytes32 extraParams,
        bytes payload,
        Fees fees
    );

    /**
     * @notice emits the status of message after inbound call
     * @param msgId msg id which is executed
     */
    event ExecutionSuccess(bytes32 msgId);

    /**
     * @notice emits the status of message after inbound call
     * @param msgId msg id which is executed
     * @param result if message reverts, returns the revert message
     */
    event ExecutionFailed(bytes32 msgId, string result);

    /**
     * @notice emits the error message in bytes after inbound call
     * @param msgId msg id which is executed
     * @param result if message reverts, returns the revert message in bytes
     */
    event ExecutionFailedBytes(bytes32 msgId, bytes result);

    /**
     * @notice emits the config set by a plug for a remoteChainSlug
     * @param plug address of plug on current chain
     * @param siblingChainSlug sibling chain slug
     * @param siblingPlug address of plug on sibling chain
     * @param inboundSwitchboard inbound switchboard (select from registered options)
     * @param outboundSwitchboard outbound switchboard (select from registered options)
     * @param capacitor capacitor selected based on outbound switchboard
     * @param decapacitor decapacitor selected based on inbound switchboard
     */
    event PlugConnected(
        address plug,
        uint32 siblingChainSlug,
        address siblingPlug,
        address inboundSwitchboard,
        address outboundSwitchboard,
        address capacitor,
        address decapacitor
    );

    /**
     * @notice emits when a new transmitManager contract is set
     * @param transmitManager address of new transmitManager contract
     */
    event TransmitManagerSet(address transmitManager);

    /**
     * @notice registers a message
     * @dev Packs the message and includes it in a packet with capacitor
     * @param remoteChainSlug_ the remote chain slug
     * @param msgGasLimit_ the gas limit needed to execute the payload on remote
     * @param payload_ the data which is needed by plug at inbound call on remote
     */
    function outbound(
        uint32 remoteChainSlug_,
        uint256 msgGasLimit_,
        bytes32 extraParams_,
        bytes calldata payload_
    ) external payable returns (bytes32 msgId);

    /**
     * @notice executes a message
     * @param packetId packet id
     * @param proposalCount proposal id for a proposal for packetId
     * @param messageDetails_ the details needed for message verification
     */
    function execute(
        bytes32 packetId,
        uint256 proposalCount,
        ISocket.MessageDetails calldata messageDetails_,
        bytes memory signature
    ) external payable;

    /**
     * @notice seals data in capacitor for specific batchSizr
     * @param batchSize_ size of batch to be sealed
     * @param capacitorAddress_ address of capacitor
     * @param signature_ signed Data needed for verification
     */
    function seal(
        uint256 batchSize_,
        address capacitorAddress_,
        bytes calldata signature_
    ) external payable;

    /**
     * @notice proposes a packet
     * @param packetId_ packet id
     * @param root_ root data
     * @param signature_ signed Data needed for verification
     */
    function propose(
        bytes32 packetId_,
        bytes32 root_,
        bytes calldata signature_
    ) external;

    /**
     * @notice sets the config specific to the plug
     * @param siblingChainSlug_ the sibling chain slug
     * @param siblingPlug_ address of plug present at sibling chain to call inbound
     * @param inboundSwitchboard_ the address of switchboard to use for receiving messages
     * @param outboundSwitchboard_ the address of switchboard to use for sending messages
     */
    function connect(
        uint32 siblingChainSlug_,
        address siblingPlug_,
        address inboundSwitchboard_,
        address outboundSwitchboard_
    ) external;

    /**
     * @notice Registers a switchboard with a specified max packet length, sibling chain slug, and capacitor type.
     * @param siblingChainSlug_ The slug of the sibling chain that the switchboard is registered with.
     * @param maxPacketLength_ The maximum length of a packet allowed by the switchboard.
     * @param capacitorType_ The type of capacitor that the switchboard uses.
     */
    function registerSwitchBoard(
        uint32 siblingChainSlug_,
        uint256 maxPacketLength_,
        uint256 capacitorType_
    ) external returns (address capacitor);

    /**
     * @notice Retrieves the packet id roots for a specified packet id.
     * @param packetId_ The packet id for which to retrieve the root.
     * @param proposalCount_ The proposal id for packetId_ for which to retrieve the root.
     * @return The packet id roots for the specified packet id.
     */
    function packetIdRoots(
        bytes32 packetId_,
        uint256 proposalCount_
    ) external view returns (bytes32);

    /**
     * @notice Retrieves the minimum fees required for a message with a specified gas limit and destination chain.
     * @param msgGasLimit_ The gas limit of the message.
     * @param remoteChainSlug_ The slug of the destination chain for the message.
     * @param plug_ The address of the plug through which the message is sent.
     * @return totalFees The minimum fees required for the specified message.
     */
    function getMinFees(
        uint256 msgGasLimit_,
        uint256 payloadSize_,
        bytes32 extraParams_,
        uint32 remoteChainSlug_,
        address plug_
    ) external view returns (uint256 totalFees);
}
