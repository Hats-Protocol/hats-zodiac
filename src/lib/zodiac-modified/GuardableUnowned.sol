// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import { BaseGuard } from "../../../lib/zodiac/contracts/guard/BaseGuard.sol";
import { IGuard } from "../../../lib/zodiac/contracts/interfaces/IGuard.sol";

/// @title Guardable - A contract that manages fallback calls made to this contract
/// @author Gnosis Guild
/// @dev Modified from Zodiac's Guardable to enable inheriting contracts to use their preferred owner logic.
/// https://github.com/gnosisguild/zodiac/blob/5165ce2f377c291d4bfe71d21948d9df0fdf6224/contracts/guard/Guardable.sol
/// Modifications:
/// - Removed owner logic
contract GuardableUnowned {
  address public guard;

  event ChangedGuard(address guard);

  /// `guard` does not implement IERC165.
  error NotIERC165Compliant(address guard);

  /// @dev Set a guard that checks transactions before execution.
  /// @param _guard The address of the guard to be used or the 0 address to disable the guard.
  function _setGuard(address _guard) internal virtual {
    if (_guard != address(0)) {
      if (!BaseGuard(_guard).supportsInterface(type(IGuard).interfaceId)) {
        revert NotIERC165Compliant(_guard);
      }
    }
    guard = _guard;
    emit ChangedGuard(_guard);
  }

  function getGuard() public view virtual returns (address _guard) {
    return guard;
  }
}
