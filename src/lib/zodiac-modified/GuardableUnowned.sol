// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import { BaseGuard } from "../../../lib/zodiac/contracts/guard/BaseGuard.sol";
import { IGuard } from "../../../lib/zodiac/contracts/interfaces/IGuard.sol";

/// @title Guardable - A contract that manages fallback calls made to this contract
/// @author Gnosis Guild
/// @dev Modified from Zodiac's Guardable to enable inheriting contracts to use their preferred owner logic.
contract GuardableUnowned {
  address internal _guard;

  event ChangedGuard(address guard);

  /// `guard` does not implement IERC165.
  error NotIERC165Compliant(address guard);

  /// @dev Set a guard that checks transactions before execution.
  /// @param guard The address of the guard to be used or the 0 address to disable the guard.
  function setGuard(address guard) public virtual {
    if (_guard != address(0)) {
      if (!BaseGuard(_guard).supportsInterface(type(IGuard).interfaceId)) {
        revert NotIERC165Compliant(_guard);
      }
    }
    _guard = guard;
    emit ChangedGuard(guard);
  }

  function getGuard() public view virtual returns (address guard) {
    return _guard;
  }
}
