// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { BaseGuard, Enum } from "zodiac/guard/BaseGuard.sol";

contract MockGuard is BaseGuard {
  address public constant TEST_ADDRESS = address(0x2);
  // doesn't allow values of over 
  function checkTransaction(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes memory signatures,
        address msgSender
    ) external override {
      require(value > 1 ether, "Guard pre-check failed.");
    }

    function checkAfterExecution(bytes32 txHash, bool success) external override {
      require(TEST_ADDRESS.balance < 2 ether, "Guard post-check failed.");
    }
}
