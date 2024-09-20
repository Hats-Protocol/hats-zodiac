// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { console2 } from "forge-std/Test.sol"; // remove after testing
import "./HatsSignerGate.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";
import { SafeProxyFactory } from "../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { ModuleProxyFactory } from "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";
import { ISafe } from "./lib/safe-interfaces/ISafe.sol";

contract HatsSignerGateFactory {
    /// @notice (Multi)HatsSignerGates cannot be used with other modules
    error NoOtherModulesAllowed();

    address public immutable hatsAddress;

    address public immutable hatsSignerGateSingleton;

    // address public immutable hatsSignerGatesingleton;
    address public immutable safeSingleton;

    // Library to use for EIP1271 compatability
    address public immutable safeFallbackLibrary;

    // Library to use for all safe transaction executions
    address public immutable safeMultisendLibrary;

    SafeProxyFactory public immutable safeProxyFactory;

    ModuleProxyFactory public immutable zodiacModuleFactory;

    string public version;

    uint256 internal nonce;

    address internal constant SENTINEL_MODULES = address(0x1);

    // events

    event HatsSignerGateSetup(
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
        address _hatsAddress,
        address _safeSingleton,
        address _safeFallbackLibrary,
        address _safeMultisendLibrary,
        address _safeProxyFactory,
        address _zodiacModuleFactory,
        string memory _version
    ) {
        hatsSignerGateSingleton = _hatsSignerGateSingleton;
        hatsAddress = _hatsAddress;
        safeSingleton = _safeSingleton;
        safeFallbackLibrary = _safeFallbackLibrary;
        safeMultisendLibrary = _safeMultisendLibrary;
        safeProxyFactory = SafeProxyFactory(_safeProxyFactory);
        zodiacModuleFactory = ModuleProxyFactory(_zodiacModuleFactory);
        version = _version;
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

    /// @notice Deploy a new HatsSignerGate and a new Safe, all wired up together
    function deployHatsSignerGateAndSafe(
        uint256 _ownerHatId,
        uint256[] calldata _signersHatIds,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address hsg, address payable safe) {
        // Deploy new safe but do not set it up yet
        safe = payable(safeProxyFactory.createProxyWithNonce(safeSingleton, hex"00", 0));

        // Deploy new hats signer gate
        hsg = _deployHatsSignerGate(_ownerHatId, _signersHatIds, safe, _minThreshold, _targetThreshold, _maxSigners);

        // Generate delegate call so the safe calls enableModule on itself during setup
        bytes memory multisendAction = _generateMultisendAction(hsg, safe);

        // Workaround for solidity dynamic memory array
        address[] memory owners = new address[](1);
        owners[0] = hsg;

        // Call setup on safe to enable our new module/guard and set it as the sole initial owner
        ISafe(safe).setup(
            owners,
            1,
            safeMultisendLibrary,
            multisendAction, // set hsg as module and guard
            safeFallbackLibrary,
            address(0),
            0,
            payable(address(0))
        );

        emit HatsSignerGateSetup(hsg, _ownerHatId, _signersHatIds, safe, _minThreshold, _targetThreshold, _maxSigners);

        return (hsg, safe);
    }

    /**
     * @notice Deploy a new HatsSignerGate and relate it to an existing Safe
     * @dev In order to wire it up to the existing Safe, the owners of the Safe must enable it as a module and guard
     *      WARNING: HatsSignerGate must not be attached to a Safe with any other modules
     *      WARNING: HatsSignerGate must not be attached to its Safe if `validSignerCount()` > `_maxSigners`
     *      Before wiring up HatsSignerGate to its Safe, call `canAttachHSGToSafe` and make sure the result is true
     *      Failure to do so may result in the Safe being locked forever
     */
    function deployHatsSignerGate(
        uint256 _ownerHatId,
        uint256[] calldata _signersHatIds,
        address _safe, // existing Gnosis Safe that the signers will join
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address hsg) {
        // // disallow attaching to a safe with existing modules
        (address[] memory modulesWith1,) = ISafe(payable(_safe)).getModulesPaginated(SENTINEL_MODULES, 1);
        if (modulesWith1.length > 0) revert NoOtherModulesAllowed();

        return _deployHatsSignerGate(_ownerHatId, _signersHatIds, _safe, _minThreshold, _targetThreshold, _maxSigners);
    }

    /**
     * @notice Checks if a HatsSignerGate can be safely attached to a Safe
     * @dev There must be...
     *      1) No existing modules on the Safe
     *      2) HatsSignerGate's `validSignerCount()` must be <= `_maxSigners`
     */
    function canAttachHSGToSafe(HatsSignerGate _hsg) public view returns (bool) {
        (address[] memory modulesWith1,) = _hsg.safe().getModulesPaginated(SENTINEL_MODULES, 1);
        uint256 moduleCount = modulesWith1.length;

        return (moduleCount == 0 && _hsg.validSignerCount() <= _hsg.maxSigners());
    }

    function _deployHatsSignerGate(
        uint256 _ownerHatId,
        uint256[] calldata _signersHatIds,
        address _safe, // existing Gnosis Safe that the signers will join
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) internal returns (address hsg) {
        bytes memory initializeParams = abi.encode(
            _ownerHatId, _signersHatIds, _safe, hatsAddress, _minThreshold, _targetThreshold, _maxSigners, version
        );

        hsg = zodiacModuleFactory.deployModule(
            hatsSignerGateSingleton, abi.encodeWithSignature("setUp(bytes)", initializeParams), ++nonce
        );

        emit HatsSignerGateSetup(hsg, _ownerHatId, _signersHatIds, _safe, _minThreshold, _targetThreshold, _maxSigners);
    }
}
