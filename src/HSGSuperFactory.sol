// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { console2 } from "forge-std/Test.sol"; // remove after testing
import "./HSGSuperMod.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSend.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";
import "@gnosis.pm/zodiac/factory/ModuleProxyFactory.sol";

contract HSGSuperFactory {
    /// @notice (Multi)HatsSignerGates cannot be used with other modules
    error NoOtherModulesAllowed();

    address public immutable hatsAddress;

    address public immutable hsgsuperSingleton;

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

    address internal constant SENTINEL_MODULES = address(0x1);

    // events

    event HSGSuperModSetup(
        address _hatsSignerGate,
        uint256 _ownerHatId,
        uint256 _signersHatId,
        address _safe,
        address _timelock,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    );

    constructor(
        address _hsgsuperSingleton,
        address _hatsAddress,
        address _safeSingleton,
        address _gnosisFallbackLibrary,
        address _gnosisMultisendLibrary,
        address _gnosisSafeProxyFactory,
        address _moduleProxyFactory,
        string memory _version
    ) {
        hsgsuperSingleton = _hsgsuperSingleton;
        hatsAddress = _hatsAddress;
        safeSingleton = _safeSingleton;
        gnosisFallbackLibrary = _gnosisFallbackLibrary;
        gnosisMultisendLibrary = _gnosisMultisendLibrary;
        gnosisSafeProxyFactory = GnosisSafeProxyFactory(_gnosisSafeProxyFactory);
        moduleProxyFactory = ModuleProxyFactory(_moduleProxyFactory);
        version = _version;
    }

    // /// @notice Deploy a new HatsSignerGate and a new Safe, all wired up together
    // function deployHSGSuperModAndSafeWithTimelock(
    //     uint256 _ownerHatId,
    //     uint256 _signersHatId,
    //     uint256 _minThreshold,
    //     uint256 _targetThreshold,
    //     uint256 _maxSigners,
    //     uint256 _minDelay
    // ) public returns (address hsg, address payable safe) {
    //     // Deploy new safe but do not set it up yet
    //     safe = payable(gnosisSafeProxyFactory.createProxy(safeSingleton, hex"00"));

    //     TimelockController timelock = new TimelockController(_minDelay, new address[](0), new address[](0), address(this));

    //     // Deploy new hats signer gate
    //     hsg = _deployHSGSuperModWithTimelock(_ownerHatId, _signersHatId, safe, payable(timelock), _minThreshold, _targetThreshold, _maxSigners);

    //     // add this (which should be the governor contract) as the canceller and add the hsg as proposer, canceller, and anyone can execute (should look into this later)
    //     timelock.grantRole(timelock.PROPOSER_ROLE(), hsg);
    //     timelock.grantRole(timelock.CANCELLER_ROLE(), hsg);
    //     timelock.grantRole(timelock.CANCELLER_ROLE(), msg.sender);
    //     timelock.renounceRole(timelock.TIMELOCK_ADMIN_ROLE(), address(this));

    //     // Generate delegate call so the safe calls enableModule on itself during setup
    //     bytes memory multisendAction = _generateMultisendAction(hsg, safe);

    //     // Workaround for solidity dynamic memory array
    //     address[] memory owners = new address[](1);
    //     owners[0] = hsg;

    //     // Call setup on safe to enable our new module/guard and set it as the sole initial owner
    //     GnosisSafe(safe).setup(
    //         owners,
    //         1,
    //         gnosisMultisendLibrary,
    //         multisendAction, // set hsg as module and guard
    //         gnosisFallbackLibrary,
    //         address(0),
    //         0,
    //         payable(address(0))
    //     );

    //     emit HSGSuperModSetup(hsg, _ownerHatId, _signersHatId, safe, address(timelock), _minThreshold, _targetThreshold, _maxSigners);

    //     return (hsg, safe);
    // }

    /// @notice Deploy a new HatsSignerGate and a new Safe, all wired up together
    function deployHSGSuperModAndSafe(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public returns (address hsg, address payable safe) {
        // Deploy new safe but do not set it up yet
        safe = payable(gnosisSafeProxyFactory.createProxy(safeSingleton, hex"00"));

        // Deploy new hats signer gate
        hsg = _deployHSGSuperMod(_ownerHatId, _signersHatId, safe, _minThreshold, _targetThreshold, _maxSigners);

        // Generate delegate call so the safe calls enableModule on itself during setup
        bytes memory multisendAction = _generateMultisendAction(hsg, safe);

        // Workaround for solidity dynamic memory array
        address[] memory owners = new address[](1);
        owners[0] = hsg;

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

        // emit HSGSuperModSetup(hsg, _ownerHatId, _signersHatId, safe, address(0), _minThreshold, _targetThreshold, _maxSigners);

        return (hsg, safe);
    }

    function _deployHSGSuperMod(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        address _safe, // existing Gnosis Safe that the signers will join
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) internal returns (address hsg) {
        bytes memory initializeParams = abi.encode(
            _ownerHatId, _signersHatId, _safe, hatsAddress, address(0), _minThreshold, _targetThreshold, _maxSigners, version
        );

        hsg = moduleProxyFactory.deployModule(
            hsgsuperSingleton, abi.encodeWithSignature("setUp(bytes)", initializeParams), ++nonce
        );

        // emit HatsSignerGateSetup(hsg, _ownerHatId, _signersHatId, _safe, _minThreshold, _targetThreshold, _maxSigners);
        // need a diff event for super mod
    }

    // function _deployHSGSuperModWithTimelock(
    //     uint256 _ownerHatId,
    //     uint256 _signersHatId,
    //     address _safe, // existing Gnosis Safe that the signers will join
    //     address payable _timelock,
    //     uint256 _minThreshold,
    //     uint256 _targetThreshold,
    //     uint256 _maxSigners
    // ) internal returns (address hsg) {
    //     bytes memory initializeParams = abi.encode(
    //         _ownerHatId, _signersHatId, _safe, hatsAddress, _timelock, _minThreshold, _targetThreshold, _maxSigners, version
    //     );

    //     hsg = moduleProxyFactory.deployModule(
    //         hsgsuperSingleton, abi.encodeWithSignature("setUp(bytes)", initializeParams), ++nonce
    //     );

    //     // emit HatsSignerGateSetup(hsg, _ownerHatId, _signersHatId, _safe, _minThreshold, _targetThreshold, _maxSigners);
    //     // need a diff event for super mod
    // }

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

}
