// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";
import { SafeProxyFactory } from "../lib/safe-smart-account/contracts/proxies/SafeProxyFactory.sol";
import { ISafe } from "./lib/safe-interfaces/ISafe.sol";

contract SafeDeployer {
  /*//////////////////////////////////////////////////////////////
                              CONSTANTS
  //////////////////////////////////////////////////////////////*/
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
