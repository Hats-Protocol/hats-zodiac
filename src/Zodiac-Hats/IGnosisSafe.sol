// SPDX-License-Identifier: CC0
pragma solidity ^0.8.4;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

interface IGnosisSafe {
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;

    function removeOwner(
        address prevOwner,
        address owner,
        uint256 _threshold
    ) external;

    function changeThreshold(uint256 _threshold) external;

    function nonce() external returns (uint256);

    function getThreshold() external returns (uint256);

    function domainSeparator() external view returns (bytes32);

    function getOwners() external view returns (address[] memory);

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success);
}
