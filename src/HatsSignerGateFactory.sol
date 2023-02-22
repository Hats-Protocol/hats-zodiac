// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import { console2 } from "forge-std/Test.sol"; // remove after testing
import "./HatsSignerGate.sol";
import "./MultiHatsSignerGate.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSend.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/zodiac/factory/ModuleProxyFactory.sol";

// import "forge-std/Test.sol"; // remove after testing

contract HatsSignerGateFactory {
    address public immutable hatsAddress;

    address public immutable hatsSignerGateSingleton;
    address public immutable multiHatsSignerGateSingleton;

    // address public immutable hatsSignerGatesingleton;
    address public immutable safeSingleton;

    // Library to use for EIP1271 compatability
    address public immutable gnosisFallbackLibrary;

    // Library to use for all safe transaction executions
    address public immutable gnosisMultisendLibrary;

    GnosisSafeProxyFactory public immutable gnosisSafeProxyFactory;

    ModuleProxyFactory public immutable moduleProxyFactory;

    string public version;

    uint256 internal nonce;

    // events

    event HatsSignerGateSetup(
        address _hatsSignerGate,
        uint256 _ownerHatId,
        uint256 _signersHatId,
        address _safe,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    );

    event MultiHatsSignerGateSetup(
        address _hatsSignerGate,
        uint256 _ownerHatId,
        uint256[] _signersHatIds,
        address _safe,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    );

    constructor(
        address _hatsSignerGateSingleton,
        address _multiHatsSignerGateSingleton,
        address _hatsAddress,
        address _safeSingleton,
        address _gnosisFallbackLibrary,
        address _gnosisMultisendLibrary,
        address _gnosisSafeProxyFactory,
        address _moduleProxyFactory,
        string memory _version
    ) {
        hatsSignerGateSingleton = _hatsSignerGateSingleton;
        multiHatsSignerGateSingleton = _multiHatsSignerGateSingleton;
        hatsAddress = _hatsAddress;
        safeSingleton = _safeSingleton;
        gnosisFallbackLibrary = _gnosisFallbackLibrary;
        gnosisMultisendLibrary = _gnosisMultisendLibrary;
        gnosisSafeProxyFactory = GnosisSafeProxyFactory(_gnosisSafeProxyFactory);
        moduleProxyFactory = ModuleProxyFactory(_moduleProxyFactory);
        version = _version;
    }

    // option 1: deploy a new Safe and signer gate, all wired up
    function deployHatsSignerGateAndSafe(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address hsg, address payable safe) {
        // Deploy new safe but do not set it up yet
        safe = payable(gnosisSafeProxyFactory.createProxy(safeSingleton, hex"00"));

        // Deploy new hats signer gate
        hsg = deployHatsSignerGate(_ownerHatId, _signersHatId, safe, _minThreshold, _targetThreshold, _maxSigners);

        // Generate delegate call so the safe calls enableModule on itself during setup
        bytes memory multisendAction = _generateMultisendAction(hsg, safe);

        // Workaround for solidity dynamic memory array
        address[] memory owners = new address[](1);
        owners[0] = hsg;
        // console2.log(address(hsg));
        // console2.log(hsg);
        // console2.log(owners[0]);

        // Call setup on safe to enable our new module/guard and set it as the sole initial owner
        GnosisSafe(safe).setup(
            owners,
            1,
            gnosisMultisendLibrary,
            multisendAction, // set hsg as module and guard
            gnosisFallbackLibrary,
            address(0),
            0,
            payable(address(0))
        );

        emit HatsSignerGateSetup(hsg, _ownerHatId, _signersHatId, safe, _minThreshold, _targetThreshold, _maxSigners);

        return (hsg, safe);
    }

    // option 2: deploy a new signer gate and attach it to an existing Safe
    /// @dev Do not attach HatsSignerGate to a Safe with existing modules; HatsSignerGate will freeze all subsequent transactions
    function deployHatsSignerGate(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        address _safe, // existing Gnosis Safe that the signers will join
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address hsg) {
        bytes memory initializeParams = abi.encode(
            _ownerHatId, _signersHatId, _safe, hatsAddress, _minThreshold, _targetThreshold, _maxSigners, version
        );

        console2.log(nonce);

        hsg = moduleProxyFactory.deployModule(
            hatsSignerGateSingleton, abi.encodeWithSignature("setUp(bytes)", initializeParams), ++nonce
        );

        console2.log(nonce);

        emit HatsSignerGateSetup(hsg, _ownerHatId, _signersHatId, _safe, _minThreshold, _targetThreshold, _maxSigners);
    }

    function _generateMultisendAction(address _hatsSignerGate, address _safe)
        internal
        pure
        returns (bytes memory _action)
    {
        bytes memory enableHSGModule = abi.encodeWithSignature("enableModule(address)", _hatsSignerGate);

        // Generate delegate call so the safe calls setGuard on itself during setup
        bytes memory setHSGGuard = abi.encodeWithSignature("setGuard(address)", _hatsSignerGate);

        bytes memory packedCalls = abi.encodePacked(
            // enableHSGModule
            uint8(0), // 0 for call; 1 for delegatecall
            _safe, // to
            uint256(0), // value
            uint256(enableHSGModule.length), // data length
            bytes(enableHSGModule), // data
            // setHSGGuard
            uint8(0), // 0 for call; 1 for delegatecall
            _safe, // to
            uint256(0), // value
            uint256(setHSGGuard.length), // data length
            bytes(setHSGGuard) // data
        );

        _action = abi.encodeWithSignature("multiSend(bytes)", packedCalls);
    }

    // option 3: deploy a new Safe and signer gate, all wired up
    function deployMultiHatsSignerGateAndSafe(
        uint256 _ownerHatId,
        uint256[] calldata _signersHatIds,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address mhsg, address payable safe) {
        // Deploy new safe but do not set it up yet
        safe = payable(gnosisSafeProxyFactory.createProxy(safeSingleton, hex"00"));

        // Deploy new hats signer gate
        mhsg =
            deployMultiHatsSignerGate(_ownerHatId, _signersHatIds, safe, _minThreshold, _targetThreshold, _maxSigners);

        // Generate delegate call so the safe calls enableModule on itself during setup
        bytes memory multisendAction = _generateMultisendAction(mhsg, safe);

        // Workaround for solidity dynamic memory array
        address[] memory owners = new address[](1);
        owners[0] = mhsg;

        // Call setup on safe to enable our new module/guard and set it as the sole initial owner
        GnosisSafe(safe).setup(
            owners,
            1,
            gnosisMultisendLibrary,
            multisendAction, // set hsg as module and guard
            gnosisFallbackLibrary,
            address(0),
            0,
            payable(address(0))
        );

        emit MultiHatsSignerGateSetup(
            mhsg, _ownerHatId, _signersHatIds, safe, _minThreshold, _targetThreshold, _maxSigners
            );

        return (mhsg, safe);
    }

    // option 2: deploy a new signer gate and attach it to an existing Safe
    /// @dev Do not attach MultiHatsSignerGate to a Safe with existing modules; MultiHatsSignerGate will freeze all subsequent transactions
    function deployMultiHatsSignerGate(
        uint256 _ownerHatId,
        uint256[] calldata _signersHatIds,
        address _safe, // existing Gnosis Safe that the signers will join
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address mhsg) {
        bytes memory initializeParams = abi.encode(
            _ownerHatId, _signersHatIds, _safe, hatsAddress, _minThreshold, _targetThreshold, _maxSigners, version
        );

        console2.log(nonce);

        mhsg = moduleProxyFactory.deployModule(
            multiHatsSignerGateSingleton, abi.encodeWithSignature("setUp(bytes)", initializeParams), ++nonce
        );

        console2.log(nonce);

        emit MultiHatsSignerGateSetup(
            mhsg, _ownerHatId, _signersHatIds, _safe, _minThreshold, _targetThreshold, _maxSigners
            );
    }
}
