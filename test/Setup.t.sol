// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/Socket.sol";
import "../src/notaries/AdminNotary.sol";
import "../src/accumulators/SingleAccum.sol";
import "../src/deaccumulators/SingleDeaccum.sol";
import "../src/verifiers/Verifier.sol";
import "../src/utils/SignatureVerifier.sol";
import "../src/utils/Hasher.sol";
import "../src/vault/Vault.sol";

contract Setup is Test {
    address constant _socketOwner = address(1);
    address constant _plugOwner = address(2);
    address constant _raju = address(4);
    address constant _pauser = address(5);
    address _attester;
    address _altAttester;

    uint256 constant _attesterPrivateKey = uint256(1);
    uint256 constant _altAttesterPrivateKey = uint256(2);

    uint256 internal _timeoutInSeconds = 0;
    uint256 internal _slowAccumWaitTime = 300;
    uint256 internal _msgGasLimit = 25548;
    string internal fastIntegrationType = "FAST";
    string internal slowIntegrationType = "SLOW";

    struct ChainContext {
        uint256 chainSlug;
        bytes32 slowAccumType;
        bytes32 fastAccumType;
        AdminNotary notary__;
        Hasher hasher__;
        IAccumulator fastAccum__;
        IAccumulator slowAccum__;
        IDeaccumulator deaccum__;
        SignatureVerifier sigVerifier__;
        Socket socket__;
        Vault vault__;
        Verifier verifier__;
    }

    struct MessageContext {
        uint256 amount;
        uint256 msgId;
        bytes32 root;
        uint256 packetId;
        bytes sig;
        bytes payload;
        bytes proof;
    }

    ChainContext _a;
    ChainContext _b;

    function _dualChainSetup(uint256[] memory attesters_, uint256 minFees_)
        internal
    {
        _a.chainSlug = uint16(uint256(0x2013AA263));
        _b.chainSlug = uint16(uint256(0x2013AA264));

        _a = _deployContractsOnSingleChain(_a.chainSlug, _b.chainSlug);
        _b = _deployContractsOnSingleChain(_b.chainSlug, _a.chainSlug);

        // setup attesters
        _addAttesters(attesters_, _a, _b.chainSlug);
        _addAttesters(attesters_, _b, _a.chainSlug);

        // add fast and slow config for all remoteChains
        _setConfig(_a, _b.chainSlug);
        _setConfig(_b, _a.chainSlug);

        // setup minfees in vault for diff accum for all remote chains
        vm.startPrank(_socketOwner);
        _a.vault__.setFees(minFees_, _a.fastAccumType);
        _a.vault__.setFees(minFees_, _a.slowAccumType);
        _b.vault__.setFees(minFees_, _b.fastAccumType);
        _b.vault__.setFees(minFees_, _b.slowAccumType);
        vm.stopPrank();
    }

    function _addAttesters(
        uint256[] memory attesterPrivateKey_,
        ChainContext memory cc_,
        uint256 remoteChainSlug_
    ) internal {
        vm.startPrank(_socketOwner);

        address attester;
        for (uint256 index = 0; index < attesterPrivateKey_.length; index++) {
            // deduce attester address from private key
            attester = vm.addr(attesterPrivateKey_[index]);
            // grant attester role
            cc_.notary__.grantAttesterRole(remoteChainSlug_, attester);
        }

        vm.stopPrank();
    }

    function _deployContractsOnSingleChain(
        uint256 localChainSlug_,
        uint256 remoteChainSlug_
    ) internal returns (ChainContext memory cc) {
        cc.chainSlug = localChainSlug_;
        (cc.sigVerifier__, cc.notary__) = _deployNotary(
            cc.chainSlug,
            _socketOwner
        );

        (cc.hasher__, cc.vault__, cc.socket__) = _deploySocket(
            cc.chainSlug,
            _socketOwner
        );

        (cc.fastAccum__, cc.deaccum__) = _deployAccumDeaccum(
            cc.notary__,
            address(cc.socket__),
            _socketOwner,
            remoteChainSlug_
        );

        (cc.slowAccum__, cc.deaccum__) = _deployAccumDeaccum(
            cc.notary__,
            address(cc.socket__),
            _socketOwner,
            remoteChainSlug_
        );

        hoax(_socketOwner);
        cc.verifier__ = new Verifier(
            _plugOwner,
            address(cc.notary__),
            address(cc.socket__),
            _timeoutInSeconds,
            keccak256(abi.encode(fastIntegrationType))
        );

        hoax(_socketOwner);
        cc.socket__.grantExecutorRole(_raju);
    }

    function _setConfig(ChainContext storage cc_, uint256 remoteChainSlug_)
        internal
    {
        hoax(_socketOwner);
        cc_.fastAccumType = cc_.socket__.addConfig(
            remoteChainSlug_,
            address(cc_.fastAccum__),
            address(cc_.deaccum__),
            address(cc_.verifier__),
            fastIntegrationType
        );

        hoax(_socketOwner);
        cc_.slowAccumType = cc_.socket__.addConfig(
            remoteChainSlug_,
            address(cc_.slowAccum__),
            address(cc_.deaccum__),
            address(cc_.verifier__),
            slowIntegrationType
        );
    }

    function _deploySocket(uint256 chainSlug_, address deployer_)
        internal
        returns (
            Hasher hasher__,
            Vault vault__,
            Socket socket__
        )
    {
        vm.startPrank(deployer_);
        hasher__ = new Hasher();
        vault__ = new Vault(deployer_);
        socket__ = new Socket(
            uint16(chainSlug_),
            address(hasher__),
            address(vault__)
        );

        vm.stopPrank();
    }

    function _deployNotary(uint256 chainSlug_, address deployer_)
        internal
        returns (SignatureVerifier sigVerifier__, AdminNotary notary__)
    {
        vm.startPrank(deployer_);
        sigVerifier__ = new SignatureVerifier();
        notary__ = new AdminNotary(address(sigVerifier__), chainSlug_);

        vm.stopPrank();
    }

    function _deployAccumDeaccum(
        AdminNotary notary__,
        address socket_,
        address deployer_,
        uint256 remoteChainSlug_
    ) internal returns (SingleAccum accum__, SingleDeaccum deaccum__) {
        vm.startPrank(deployer_);

        accum__ = new SingleAccum(socket_, address(notary__), remoteChainSlug_);
        deaccum__ = new SingleDeaccum();

        vm.stopPrank();
    }

    function _getLatestSignature(
        ChainContext storage src_,
        address accum_,
        uint256 remoteChainSlug_
    )
        internal
        returns (
            bytes32 root,
            uint256 packetId,
            bytes memory sig
        )
    {
        (root, packetId, sig) = _getLatestSignatureForSigner(
            src_,
            accum_,
            remoteChainSlug_,
            _attesterPrivateKey
        );
    }

    function _getLatestSignatureForSigner(
        ChainContext storage src_,
        address accum_,
        uint256 remoteChainSlug_,
        uint256 privateKey_
    )
        internal
        returns (
            bytes32 root,
            uint256 packetId,
            bytes memory sig
        )
    {
        (root, packetId) = IAccumulator(accum_).getNextPacketToBeSealed();

        bytes32 digest = keccak256(
            abi.encode(src_.chainSlug, remoteChainSlug_, accum_, packetId, root)
        );
        digest = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", digest)
        );

        (uint8 sigV, bytes32 sigR, bytes32 sigS) = vm.sign(privateKey_, digest);
        sig = new bytes(65);
        bytes1 v32 = bytes1(sigV);

        assembly {
            mstore(add(sig, 96), v32)
            mstore(add(sig, 32), sigR)
            mstore(add(sig, 64), sigS)
        }
    }

    function _sealOnSrc(
        ChainContext storage src_,
        address accum,
        bytes memory sig_
    ) internal {
        hoax(_attester);
        src_.notary__.seal(accum, sig_);
    }

    function _submitRootOnDst(
        ChainContext storage src_,
        ChainContext storage dst_,
        bytes memory sig_,
        uint256 packetId_,
        bytes32 root_,
        address accum_
    ) internal {
        hoax(_raju);
        dst_.notary__.propose(src_.chainSlug, accum_, packetId_, root_, sig_);
    }

    function _executePayloadOnDst(
        ChainContext storage src_,
        ChainContext storage dst_,
        address remotePlug_,
        uint256 packetId_,
        uint256 msgId_,
        uint256 msgGasLimit_,
        address accum_,
        bytes memory payload_,
        bytes memory proof_
    ) internal {
        hoax(_raju);

        ISocket.VerificationParams memory vParams = ISocket.VerificationParams(
            src_.chainSlug,
            packetId_,
            accum_,
            proof_
        );

        dst_.socket__.execute(
            msgGasLimit_,
            msgId_,
            remotePlug_,
            payload_,
            vParams
        );
    }

    function _packMessageId(
        address srcPlug,
        uint256 srcChainSlug,
        uint256 remoteChainSlug,
        uint256 nonce
    ) internal pure returns (uint256) {
        return
            (uint256(uint160(srcPlug)) << 96) |
            (srcChainSlug << 80) |
            (remoteChainSlug << 64) |
            nonce;
    }

    // to ignore this file from coverage
    function test() external {
        assertTrue(true);
    }
}
