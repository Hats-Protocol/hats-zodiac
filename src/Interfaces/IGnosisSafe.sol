// SPDX-License-Identifier: CC0
pragma solidity ^0.8.4;

import "@gnosis.pm/safe-contracts/contracts/common/Enum.sol";

interface IGnosisSafe {
    function addOwnerWithThreshold(address owner, uint256 _threshold) external;

    function swapOwner(
        address prevOwner,
        address oldOwner,
        address newOwner
    ) external;

    function removeOwner(
        address prevOwner,
        address owner,
        uint256 _threshold
    ) external;

    function changeThreshold(uint256 _threshold) external;

    function nonce() external returns (uint256);

    function getThreshold() external returns (uint256);

    function approvedHashes(address approver, bytes32 hash)
        external
        returns (uint256);

    function domainSeparator() external view returns (bytes32);

    function getOwners() external view returns (address[] memory);

    function setGuard(address guard) external;

    function execTransactionFromModule(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) external returns (bool success);

    function getTransactionHash(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 _nonce
    ) external view returns (bytes32);

    function isOwner(address owner) external returns (bool);
}
