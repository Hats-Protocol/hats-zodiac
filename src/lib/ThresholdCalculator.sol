// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

contract ThresholdCalculator {
  uint256 public minThreshold;
  uint256 public targetThreshold;
  

  /*//////////////////////////////////////////////////////////////
                            CUSTOM ERRORS
  //////////////////////////////////////////////////////////////*/

  /// @notice Target threshold must greater than `minThreshold`
  error InvalidTargetThreshold();

  /// @notice Min threshold cannot be higher than `targetThreshold`
  error InvalidMinThreshold();

  /*//////////////////////////////////////////////////////////////
                              EVENTS
  //////////////////////////////////////////////////////////////*/

  /// @notice Emitted when a new target signature threshold for the `safe` is set
  event TargetThresholdSet(uint256 threshold);

  /// @notice Emitted when a new minimum signature threshold for the `safe` is set
  event MinThresholdSet(uint256 threshold);

   /// @dev Internal function to set the target threshold. Reverts if `_targetThreshold` is lower than `minThreshold`
  /// @param _targetThreshold The new target threshold to set
  function _setTargetThreshold(uint256 _targetThreshold) internal {
    // target threshold cannot be lower than min threshold
    if (_targetThreshold < minThreshold) revert InvalidTargetThreshold();

    targetThreshold = _targetThreshold;
    emit TargetThresholdSet(_targetThreshold);
  }

  /// @dev Internal function to set a new minimum threshold. Only callable by a wearer of the owner hat.
  /// Reverts if `_minThreshold` is greater than `targetThreshold`
  /// @param _minThreshold The new minimum threshold
  function _setMinThreshold(uint256 _minThreshold) internal {
    if (_minThreshold > targetThreshold) revert InvalidMinThreshold();

    minThreshold = _minThreshold;
    emit MinThresholdSet(_minThreshold);
  }

  function _getCorrectThreshold(uint256 numOwners) internal view returns (uint256 correctThreshold)   {
    uint256 min = minThreshold;
    uint256 max = targetThreshold;
    if (numOwners < min) correctThreshold = min;
    else if (numOwners > max) correctThreshold = max;
    else correctThreshold = numOwners;
  }    
}
