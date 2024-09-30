// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { console2 } from "forge-std/console2.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";
import { SafeProxyFactory } from "../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { StorageAccessible } from "lib/safe-smart-account/contracts/common/StorageAccessible.sol";
import { Enum, ISafe, IModuleManager, IGuardManager } from "./lib/safe-interfaces/ISafe.sol";

// TODO rename to SafeManager?
contract SafeDeployer {
  /*//////////////////////////////////////////////////////////////
                              CONSTANTS
  //////////////////////////////////////////////////////////////*/
  /// @dev The head pointer used in the Safe owners linked list, as well as the module linked list
  address internal constant SENTINELS = address(0x1);

  /// @dev The storage slot used by Safe to store the guard address
  ///      keccak256("guard_manager.guard.address")
  bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

  address public immutable safeSingleton;
  address public immutable safeFallbackLibrary;
  address public immutable safeMultisendLibrary;
  SafeProxyFactory public immutable safeProxyFactory;

  /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
  //////////////////////////////////////////////////////////////*/
  constructor(
    address _safeSingleton,
    address _safeFallbackLibrary,
    address _safeMultisendLibrary,
    address _safeProxyFactory
  ) {
    safeProxyFactory = SafeProxyFactory(_safeProxyFactory);
    safeSingleton = _safeSingleton;
    safeFallbackLibrary = _safeFallbackLibrary;
    safeMultisendLibrary = _safeMultisendLibrary;
  }

  /*//////////////////////////////////////////////////////////////
                            INTERNAL LOGIC
  //////////////////////////////////////////////////////////////*/
  /// @dev Deploy a new Safe and attach HSG to it
  function _deploySafeAndAttachHSG() internal returns (address payable _safe) {
    _safe = payable(safeProxyFactory.createProxyWithNonce(safeSingleton, hex"00", 0));

    // Prepare calls to enable HSG as module and set it as guard
    bytes memory enableHSGModule = _encodeEnableModuleAction(address(this));
    bytes memory setHSGGuard = _encodeSetGuardAction(address(this));

    bytes memory packedCalls = abi.encodePacked(
      // enableHSGModule
      Enum.Operation.Call, // 0 for call; 1 for delegatecall
      _safe, // to
      uint256(0), // value
      uint256(enableHSGModule.length), // data length
      bytes(enableHSGModule), // data
      // setHSGGuard
      Enum.Operation.Call, // 0 for call; 1 for delegatecall
      _safe, // to
      uint256(0), // value
      uint256(setHSGGuard.length), // data length
      bytes(setHSGGuard) // data
    );

    bytes memory attachHSGAction = abi.encodeWithSelector(MultiSend.multiSend.selector, packedCalls);

    // Workaround for solidity dynamic memory array
    address[] memory owners = new address[](1);
    owners[0] = address(this);

    // Call setup on safe to enable our new module/guard and set it as the sole initial owner
    ISafe(_safe).setup(
      owners,
      1,
      safeMultisendLibrary,
      attachHSGAction, // set hsg as module and guard
      safeFallbackLibrary,
      address(0),
      0,
      payable(address(0))
    );
  }

  /// @dev Encode the action to enable a module
  function _encodeEnableModuleAction(address _moduleToEnable) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IModuleManager.enableModule.selector, _moduleToEnable);
  }

  /// @dev Encode the action to disable a module `_moduleToDisable`
  /// @param _previousModule The previous module in the modules linked list
  function _encodeDisableModuleAction(address _previousModule, address _moduleToDisable)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(IModuleManager.disableModule.selector, _previousModule, _moduleToDisable);
  }

  // /// @dev Encode the action to disable a module when it is the only module enabled
  // function _encodeDisableOnlyModuleAction(address _moduleToDisable) internal pure returns (bytes memory) {
  //   return _encodeDisableModuleAction(SENTINELS, _moduleToDisable);
  // }

  /// @dev Encode the action to set a `_guard`
  function _encodeSetGuardAction(address _guard) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IGuardManager.setGuard.selector, _guard);
  }

  /// @dev Encode the action to remove HSG as a guard
  function _encodeRemoveHSGAsGuardAction() internal pure returns (bytes memory) {
    // Generate calldata to remove HSG as a guard
    return _encodeSetGuardAction(address(0));
  }

  /// @dev Execute a transaction with `_data` from the context of a `_safe`
  function _execTransactionFromHSG(ISafe _safe, bytes memory _data) internal returns (bool success) {
    success =
      _safe.execTransactionFromModule({ to: address(_safe), value: 0, data: _data, operation: Enum.Operation.Call });
  }

  /// @dev Encode the action to disable HSG as a module when there are no other modules enabled on a `_safe`
  function _disableHSGAsOnlyModule(ISafe _safe) internal {
    // Generate calldata to remove HSG as a module
    bytes memory removeHSGModule = _encodeDisableModuleAction(SENTINELS, address(this));

    _execTransactionFromHSG(_safe, removeHSGModule);
  }

  /// @dev Encode the action to disable HSG as a module on a `_safe`
  /// @param _previousModule The previous module in the modules linked list
  function _disableHSGAsModule(ISafe _safe, address _previousModule) internal {
    bytes memory removeHSGModule = _encodeDisableModuleAction(_previousModule, address(this));

    _execTransactionFromHSG(_safe, removeHSGModule);
  }

  /// @dev Remove HSG as a guard on a `_safe`
  /// @param _safe The Safe from which to remove HSG as a guard
  function _removeHSGAsGuard(ISafe _safe) internal {
    bytes memory removeHSGGuard = _encodeSetGuardAction(address(0));

    _execTransactionFromHSG(_safe, removeHSGGuard);
  }

  /// @dev Attach a new HSG `_newHSG` to a `_safe`
  function _attachNewHSGFromHSG(ISafe _safe, address _newHSG) internal {
    bytes memory attachHSGModule = _encodeEnableModuleAction(_newHSG);
    bytes memory setHSGGuard = _encodeSetGuardAction(_newHSG);

    _execTransactionFromHSG(_safe, setHSGGuard);
    _execTransactionFromHSG(_safe, attachHSGModule);
  }

  /// @dev Get the guard of a `_safe`
  function _getSafeGuard(address _safe) internal view returns (address) {
    return abi.decode(StorageAccessible(_safe).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address));
  }
}
