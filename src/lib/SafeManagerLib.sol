// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

// import { console2 } from "../lib/forge-std/src/console2.sol";
import { MultiSend } from "../../lib/safe-smart-account/contracts/libraries/MultiSend.sol";
import { SafeProxyFactory } from "../../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { StorageAccessible } from "../../lib/safe-smart-account/contracts/common/StorageAccessible.sol";
import { Enum, ISafe, IGuardManager, IModuleManager, IOwnerManager } from "../lib/safe-interfaces/ISafe.sol";

/// @title SafeManagerLib
/// @author Haberdasher Labs
/// @author @spengrah
/// @notice A library for managing Safe contract settings via a HatsSignerGate module
library SafeManagerLib {
  /*//////////////////////////////////////////////////////////////
                              CUSTOM ERRORS
  //////////////////////////////////////////////////////////////*/

  /// @notice Emitted when a call to change the threshold fails
  error FailedExecChangeThreshold();

  /// @notice Emitted when a call to add a signer fails
  error FailedExecAddSigner();

  /// @notice Emitted when a call to remove a signer fails
  error FailedExecRemoveSigner();

  /// @notice Emitted when a call to enable a module fails
  error FailedExecEnableModule();

  /*//////////////////////////////////////////////////////////////
                              CONSTANTS
  //////////////////////////////////////////////////////////////*/

  /// @dev The head pointer used in the Safe owners linked list, as well as the module linked list
  address internal constant SENTINELS = address(0x1);

  /// @dev The storage slot used by Safe to store the guard address: keccak256("guard_manager.guard.address")
  bytes32 internal constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

  // keccak256("fallback_manager.handler.address")
  bytes32 internal constant FALLBACK_HANDLER_STORAGE_SLOT =
    0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

  /*//////////////////////////////////////////////////////////////
                              HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @dev Deploy a new Safe and attach HSG to it
  /// @param _safeProxyFactory The address of the SafeProxyFactory to use for deploying the Safe
  /// @param _safeSingleton The address of the Safe singleton to use as the implementation for the Safe instance
  /// @param _safeFallbackLibrary The address of the Safe fallback library to set on the Safe
  /// @param _safeMultisendLibrary The address of the Safe multisend library to use to initialize the Safe and HSG
  function deploySafeAndAttachHSG(
    address _safeProxyFactory,
    address _safeSingleton,
    address _safeFallbackLibrary,
    address _safeMultisendLibrary
  ) internal returns (address payable _safe) {
    _safe = payable(SafeProxyFactory(_safeProxyFactory).createProxyWithNonce(_safeSingleton, hex"00", 0));

    // Prepare calls to enable HSG as module and set it as guard
    bytes memory enableHSGModule = encodeEnableModuleAction(address(this));
    bytes memory setHSGGuard = encodeSetGuardAction(address(this));

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
      _safeMultisendLibrary,
      attachHSGAction, // set hsg as module and guard
      _safeFallbackLibrary,
      address(0),
      0,
      payable(address(0))
    );
  }

  /*//////////////////////////////////////////////////////////////
                  ENCODING HELPER FUNCTIONS — MODULES
  //////////////////////////////////////////////////////////////*/

  /// @dev Encode the action to enable a module
  function encodeEnableModuleAction(address _moduleToEnable) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IModuleManager.enableModule.selector, _moduleToEnable);
  }

  /// @dev Encode the action to disable a module `_moduleToDisable`
  /// @param _previousModule The previous module in the modules linked list
  function encodeDisableModuleAction(address _previousModule, address _moduleToDisable)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(IModuleManager.disableModule.selector, _previousModule, _moduleToDisable);
  }

  /*//////////////////////////////////////////////////////////////
                  ENCODING HELPER FUNCTIONS — GUARDS
  //////////////////////////////////////////////////////////////*/

  /// @dev Encode the action to set a `_guard`
  function encodeSetGuardAction(address _guard) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IGuardManager.setGuard.selector, _guard);
  }

  /// @dev Encode the action to remove HSG as a guard
  function encodeRemoveHSGAsGuardAction() internal pure returns (bytes memory) {
    // Generate calldata to remove HSG as a guard
    return encodeSetGuardAction(address(0));
  }

  /*//////////////////////////////////////////////////////////////
                  ENCODING HELPER FUNCTIONS — OWNERS
  //////////////////////////////////////////////////////////////*/

  /// @dev Encode the action to swap the owner of a `_safe` from `_oldOwner` to `_newOwner`
  function encodeSwapOwnerAction(address _prevOwner, address _oldOwner, address _newOwner)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(IOwnerManager.swapOwner.selector, _prevOwner, _oldOwner, _newOwner);
  }

  /// @dev Encode the action to remove an `_oldOwner` from a `_safe`, setting a `_newThreshold`
  /// @param _prevOwner The previous owner in the owners linked list
  function encodeRemoveOwnerAction(address _prevOwner, address _oldOwner, uint256 _newThreshold)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(IOwnerManager.removeOwner.selector, _prevOwner, _oldOwner, _newThreshold);
  }

  /// @dev Encode the action to add an `_owner` to a `_safe`, setting a `_newThreshold`
  function encodeAddOwnerWithThresholdAction(address _owner, uint256 _newThreshold)
    internal
    pure
    returns (bytes memory)
  {
    return abi.encodeWithSelector(IOwnerManager.addOwnerWithThreshold.selector, _owner, _newThreshold);
  }

  /*//////////////////////////////////////////////////////////////
                  ENCODING HELPER FUNCTIONS — THRESHOLD
  //////////////////////////////////////////////////////////////*/

  /// @dev Encode the action to change the threshold of a `_safe` to `_newThreshold`
  function encodeChangeThresholdAction(uint256 _newThreshold) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IOwnerManager.changeThreshold.selector, _newThreshold);
  }

  /*//////////////////////////////////////////////////////////////
                       EXECUTION HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @dev Execute a transaction with `_data` from the context of a `_safe`
  function execSafeTransactionFromHSG(ISafe _safe, bytes memory _data) internal {
    _safe.execTransactionFromModule({ to: address(_safe), value: 0, data: _data, operation: Enum.Operation.Call });
  }

  /// @dev Encode the action to disable HSG as a module when there are no other modules enabled on a `_safe`
  function execDisableHSGAsOnlyModule(ISafe _safe) internal {
    // Generate calldata to remove HSG as a module
    bytes memory removeHSGModule = encodeDisableModuleAction(SENTINELS, address(this));

    // execute the call
    execSafeTransactionFromHSG(_safe, removeHSGModule);
  }

  /// @dev Encode the action to disable HSG as a module on a `_safe`
  /// @param _previousModule The previous module in the modules linked list
  function execDisableHSGAsModule(ISafe _safe, address _previousModule) internal {
    bytes memory removeHSGModule = encodeDisableModuleAction(_previousModule, address(this));

    execSafeTransactionFromHSG(_safe, removeHSGModule);
  }

  /// @dev Remove HSG as a guard on a `_safe`
  /// @param _safe The Safe from which to remove HSG as a guard
  function execRemoveHSGAsGuard(ISafe _safe) internal {
    bytes memory removeHSGGuard = encodeSetGuardAction(address(0));

    execSafeTransactionFromHSG(_safe, removeHSGGuard);
  }

  /// @dev Attach a new HSG `_newHSG` to a `_safe`
  function execAttachNewHSG(ISafe _safe, address _newHSG) internal {
    bytes memory attachHSGModule = encodeEnableModuleAction(_newHSG);
    bytes memory setHSGGuard = encodeSetGuardAction(_newHSG);

    execSafeTransactionFromHSG(_safe, setHSGGuard);
    execSafeTransactionFromHSG(_safe, attachHSGModule);
  }

  /// @dev Execute the action to change the threshold of a `_safe` to `_newThreshold`
  function execChangeThreshold(ISafe _safe, uint256 _newThreshold) internal {
    execSafeTransactionFromHSG(_safe, encodeChangeThresholdAction(_newThreshold));
  }

  /*//////////////////////////////////////////////////////////////
                        VIEW HELPER FUNCTIONS
  //////////////////////////////////////////////////////////////*/

  /// @dev Get the guard of a `_safe`
  function getSafeGuard(ISafe _safe) internal view returns (address) {
    return abi.decode(StorageAccessible(address(_safe)).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address));
  }

  /// @dev Get the fallback handler of a `_safe`
  function getSafeFallbackHandler(ISafe _safe) internal view returns (address) {
    return
      abi.decode(StorageAccessible(address(_safe)).getStorageAt(uint256(FALLBACK_HANDLER_STORAGE_SLOT), 1), (address));
  }

  /// @dev Get the modules array of a `_safe` with pagination of 1
  /// @return modulesWith1 The modules array of length 1
  /// @return next A pointer to the next module in the linked list
  function getModulesWith1(ISafe _safe) internal view returns (address[] memory modulesWith1, address next) {
    (modulesWith1, next) = _safe.getModulesPaginated(SENTINELS, 1);
  }

  /// @notice Checks if a HatsSignerGate can be safely attached to a `_safe`
  /// @dev There must be no existing modules on the `_safe`
  function canAttachHSG(ISafe _safe) internal view returns (bool) {
    (address[] memory modulesWith1,) = _safe.getModulesPaginated(SENTINELS, 1);

    return (modulesWith1.length == 0);
  }

  /// @notice Internal function to find the previous owner of an `_owner` in an array of `_owners`, ie the pointer to
  /// the owner to remove from the `safe` owners linked list
  /// @param _owners An array of addresses
  /// @param _owner The address after the one to find
  /// @return prevOwner The owner previous to `_owner` in the `safe` linked list
  function findPrevOwner(address[] memory _owners, address _owner) internal pure returns (address prevOwner) {
    prevOwner = SENTINELS;

    for (uint256 i; i < _owners.length; ++i) {
      if (_owners[i] == _owner) {
        if (i == 0) break;
        prevOwner = _owners[i - 1];
      }
    }
  }
}
