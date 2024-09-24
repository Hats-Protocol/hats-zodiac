// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

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
  function _deploySafeAndAttachHSG() internal returns (address payable _safe) {
    _safe = _deploySafe();
    _attachHSG(_safe);
  }

  function _deploySafe() internal returns (address payable _safe) {
    // Deploy new safe but do not set it up yet
    _safe = payable(safeProxyFactory.createProxyWithNonce(safeSingleton, hex"00", 0));
  }

  function _attachHSG(address payable _safe) internal {
    bytes memory multisendAction = _generateMultisendAction(address(this), _safe);

    // Workaround for solidity dynamic memory array
    address[] memory owners = new address[](1);
    owners[0] = address(this);

    // Call setup on safe to enable our new module/guard and set it as the sole initial owner
    ISafe(_safe).setup(
      owners,
      1,
      safeMultisendLibrary,
      multisendAction, // set hsg as module and guard
      safeFallbackLibrary,
      address(0),
      0,
      payable(address(0))
    );
  }

  function _generateMultisendAction(address _hatsSignerGate, address _safe)
    internal
    pure
    returns (bytes memory _action)
  {
    bytes memory enableHSGModule = _encodeEnableModuleAction(_hatsSignerGate);
    bytes memory setHSGGuard = _encodeSetGuardAction(_hatsSignerGate);

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

    _action = abi.encodeWithSignature("multiSend(bytes)", packedCalls);
  }

  function _encodeEnableModuleAction(address _moduleToEnable) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IModuleManager.enableModule.selector, _moduleToEnable);
  }

  /// @dev Assumes the module is the only module enabled
  function _encodeDisableModuleAction(address _moduleToDisable) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IModuleManager.disableModule.selector, SENTINELS, _moduleToDisable);
  }

  function _encodeSetGuardAction(address _guard) internal pure returns (bytes memory) {
    return abi.encodeWithSelector(IGuardManager.setGuard.selector, _guard);
  }

  function _detachHSG(ISafe _safe) internal {
    // Generate calldata to disable HSG as a module
    bytes memory disableHSGModule = _encodeDisableModuleAction(address(this));
    // Generate calldata to remove HSG as a guard
    bytes memory removeHSGGuard = _encodeSetGuardAction(address(0));

    // TODO optimization: is this cheaper than making two direct calles via execTransactionFromModule?
    // Pack the calls to prepare for a multisend
    bytes memory packedCalls = abi.encodePacked(
      // disableHSGModule
      Enum.Operation.Call,
      _safe, // to
      uint256(0), // value
      uint256(disableHSGModule.length), // data length
      bytes(disableHSGModule), // data
      // removeHSGGuards
      Enum.Operation.Call,
      _safe, // to
      uint256(0), // value
      uint256(removeHSGGuard.length), // data length
      bytes(removeHSGGuard) // data
    );

    // Encode the multisend calldata
    bytes memory action = abi.encodeWithSelector(MultiSend.multiSend.selector, packedCalls);

    // Execute the call
    _safe.execTransactionFromModule({
      to: safeMultisendLibrary,
      value: 0,
      data: action,
      operation: Enum.Operation.DelegateCall
    });
  }

  function _getSafeGuard(address _safe) internal view returns (address) {
    return abi.decode(StorageAccessible(_safe).getStorageAt(uint256(GUARD_STORAGE_SLOT), 1), (address));
  }
}
