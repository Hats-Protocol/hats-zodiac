// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.7.0 <0.9.0;

import { IERC165 } from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import { BaseGuard } from "../../lib/zodiac/contracts/guard/BaseGuard.sol";
import { Enum } from "../../lib/safe-smart-account/contracts/common/Enum.sol";

/* solhint-disable */

/// @notice Modified from Zodiac's TestGuard to allow for disallowing execution in checkAfterExecution
/// https://github.com/gnosisguild/zodiac/blob/5165ce2f377c291d4bfe71d21948d9df0fdf6224/contracts/test/TestGuard.sol
contract TestGuard is BaseGuard {
  event PreChecked(address sender);
  event PostChecked(bool checked);

  address public module;
  bool public executionDisallowed;

  constructor(address _module) {
    bytes memory initParams = abi.encode(_module);
    setUp(initParams);
  }

  function setModule(address _module) public {
    module = _module;
  }

  /// @dev Disallows execution by causing a revert in checkAfterExecution. Useful for testing checkAfterExecution.
  function disallowExecution() public {
    executionDisallowed = true;
  }

  function checkTransaction(
    address to,
    uint256 value,
    bytes memory data,
    Enum.Operation operation,
    uint256,
    uint256,
    uint256,
    address,
    address payable,
    bytes memory,
    address sender
  ) public override {
    require(to != address(0), "Cannot send to zero address");
    require(value != 1337, "Cannot send 1337");
    require(bytes3(data) != bytes3(0xbaddad), "Cannot call 0xbaddad");
    require(operation != Enum.Operation(1), "No delegate calls");
    emit PreChecked(sender);
  }

  function checkAfterExecution(bytes32, bool) public override {
    // revert if execution is disallowed
    require(!executionDisallowed, "Reverted in checkAfterExecution");

    emit PostChecked(true);
  }

  function setUp(bytes memory initializeParams) public {
    address _module = abi.decode(initializeParams, (address));
    module = _module;
  }
}
