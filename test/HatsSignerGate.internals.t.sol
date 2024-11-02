// SPDX-License-Identifier: MIT
pragma solidity >=0.8.13;

import { Test, console2 } from "../lib/forge-std/src/Test.sol";
import { Enum, ISafe, TestSuite, WithHSGHarnessInstanceTest, HatsSignerGate } from "./TestSuite.t.sol";
import { IHats, IHatsSignerGate } from "../src/interfaces/IHatsSignerGate.sol";
import { DeployInstance } from "../script/HatsSignerGate.s.sol";
import { IAvatar } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { IModuleManager } from "../src/lib/safe-interfaces/IModuleManager.sol";
import { GuardableUnowned } from "../src/lib/zodiac-modified/GuardableUnowned.sol";
import { ModifierUnowned } from "../src/lib/zodiac-modified/ModifierUnowned.sol";
import { TestGuard } from "./mocks/TestGuard.sol";
import { MultiSend } from "../lib/safe-smart-account/contracts/libraries/MultiSend.sol";

contract AuthInternals is WithHSGHarnessInstanceTest {
  function test_happy_checkOwner() public {
    vm.prank(owner);
    harness.exposed_checkOwner();
  }

  function test_revert_checkOwner_notOwner() public {
    for (uint256 i; i < fuzzingAddresses.length; i++) {
      vm.expectRevert(abi.encodeWithSelector(IHatsSignerGate.NotOwnerHatWearer.selector));
      vm.prank(fuzzingAddresses[i]);
      harness.exposed_checkOwner();
    }
  }

  function test_happy_checkUnlocked() public view {
    // the harness starts out as unlocked, so this call should not revert
    harness.exposed_checkUnlocked();
  }

  function test_revert_checkUnlocked_locked() public {
    // lock the harness
    harness.exposed_lock();

    // confirm that its locked
    assertEq(harness.locked(), true, "harness should be locked");

    // checkUnlocked should revert
    vm.expectRevert(IHatsSignerGate.Locked.selector);
    harness.exposed_checkUnlocked();
  }
}

contract OwnerSettingsInternals is WithHSGHarnessInstanceTest {
  function test_lock() public {
    harness.exposed_lock();

    assertEq(harness.locked(), true, "harness should be locked");
  }

  function test_fuzz_setOwnerHat(uint256 _newOwnerHat) public {
    vm.expectEmit();
    emit IHatsSignerGate.OwnerHatSet(_newOwnerHat);
    harness.exposed_setOwnerHat(_newOwnerHat);

    assertEq(harness.ownerHat(), _newOwnerHat, "ownerHat should be set to the new ownerHat");
  }

  function test_fuzz_setClaimableFor(bool _claimableFor) public {
    vm.expectEmit();
    emit IHatsSignerGate.ClaimableForSet(_claimableFor);
    harness.exposed_setClaimableFor(_claimableFor);

    assertEq(harness.claimableFor(), _claimableFor, "claimableFor should be set to the new claimableFor");
  }

  function test_fuzz_addSignerHats(uint256[] memory _signerHats) public {
    vm.assume(_signerHats.length > 0);

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(_signerHats);
    harness.exposed_addSignerHats(_signerHats);

    for (uint256 i; i < _signerHats.length; i++) {
      assertTrue(harness.isValidSignerHat(_signerHats[i]), "signerHat should be valid");
    }
  }

  function test_addSignerHats_emptyArray() public {
    uint256[] memory empty = new uint256[](0);

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(empty);
    harness.exposed_addSignerHats(empty);
  }

  function test_addSignerHats_duplicateHats() public {
    uint256 hatToDuplicate = 1;
    uint256[] memory duplicates = new uint256[](2);
    duplicates[0] = hatToDuplicate;
    duplicates[1] = hatToDuplicate;

    vm.expectEmit();
    emit IHatsSignerGate.SignerHatsAdded(duplicates);
    harness.exposed_addSignerHats(duplicates);

    assertTrue(harness.isValidSignerHat(hatToDuplicate), "signerHat should be valid");
  }

  function test_fuzz_setDelegatecallTarget(uint256 _targetIndex, bool _enabled) public {
    // bound the target index
    vm.assume(_targetIndex < fuzzingAddresses.length);

    address target = fuzzingAddresses[_targetIndex];

    // set the delegatecall target
    vm.expectEmit();
    emit IHatsSignerGate.DelegatecallTargetEnabled(target, _enabled);
    harness.exposed_setDelegatecallTarget(target, _enabled);

    // now set it to the opposite enabled state
    vm.expectEmit();
    emit IHatsSignerGate.DelegatecallTargetEnabled(target, !_enabled);
    harness.exposed_setDelegatecallTarget(target, !_enabled);
  }

  // function test_setThresholdConfig(uint8 _type, uint120 _min, uint120 _target) public { }

  function test_fuzz_setThresholdConfig_valid(uint8 _type, uint120 _min, uint120 _target) public {
    // ensure the threshold type is valid
    vm.assume(uint8(_type) < 2);
    IHatsSignerGate.TargetThresholdType targetType = IHatsSignerGate.TargetThresholdType(_type);

    // ensure the min is valid
    vm.assume(_min > 0);

    // ensure the target is valid
    if (targetType == IHatsSignerGate.TargetThresholdType.ABSOLUTE) {
      vm.assume(_target >= _min);
    } else {
      vm.assume(_target <= 10_000);
    }

    IHatsSignerGate.ThresholdConfig memory config =
      IHatsSignerGate.ThresholdConfig({ thresholdType: targetType, min: _min, target: _target });

    vm.expectEmit();
    emit IHatsSignerGate.ThresholdConfigSet(config);
    harness.exposed_setThresholdConfig(config);

    assertEq(
      abi.encode(harness.thresholdConfig()),
      abi.encode(config),
      "thresholdConfig should be set to the new thresholdConfig"
    );
  }

  function test_fuzz_revert_setThresholdConfig_invalidMin(uint8 _type, uint120 _target) public {
    // ensure the threshold type is valid
    vm.assume(uint8(_type) < 2);
    IHatsSignerGate.TargetThresholdType targetType = IHatsSignerGate.TargetThresholdType(_type);

    // ensure the min is invalid
    uint120 min = 0;

    // ensure the target is valid
    if (targetType == IHatsSignerGate.TargetThresholdType.ABSOLUTE) {
      vm.assume(_target >= min);
    } else {
      vm.assume(_target <= 10_000);
    }

    IHatsSignerGate.ThresholdConfig memory config =
      IHatsSignerGate.ThresholdConfig({ thresholdType: targetType, min: min, target: _target });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    harness.exposed_setThresholdConfig(config);
  }

  function test_fuzz_revert_setThresholdConfig_invalidAbsoluteTarget(uint120 _min, uint120 _target) public {
    // ensure the min is valid
    vm.assume(_min > 0);

    // ensure the target is invalid
    vm.assume(_target < _min);

    IHatsSignerGate.ThresholdConfig memory config = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.ABSOLUTE,
      min: _min,
      target: _target
    });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    harness.exposed_setThresholdConfig(config);
  }

  function test_fuzz_revert_setThresholdConfig_invalidProportionalTarget(uint120 _min, uint120 _target) public {
    // ensure the min is valid
    vm.assume(_min > 0);

    // ensure the target is invalid
    vm.assume(_target > 10_000);

    IHatsSignerGate.ThresholdConfig memory config = IHatsSignerGate.ThresholdConfig({
      thresholdType: IHatsSignerGate.TargetThresholdType.PROPORTIONAL,
      min: _min,
      target: _target
    });

    vm.expectRevert(IHatsSignerGate.InvalidThresholdConfig.selector);
    harness.exposed_setThresholdConfig(config);
  }

  function test_fuzz_revert_setThresholdConfig_invalidThresholdType(uint8 _type, uint120 _min, uint120 _target) public {
    // ensure the threshold type is invalid
    vm.assume(uint8(_type) > 1);

    bytes memory rawConfig = abi.encode(uint8(_type), _min, _target); // thresholdType, min, target
    bytes memory callData = abi.encodeWithSelector(harness.exposed_setThresholdConfig.selector, rawConfig);

    (bool success,) = address(harness).call(callData);

    assertFalse(success, "setThresholdConfig should revert");
  }
}

contract SignerManagementInternals is WithHSGHarnessInstanceTest {
  function test_registerSigner() public { }

  function test_revert_registerSigner_invalidHat() public { }

  function test_revert_registerSigner_notSignerHatWearer() public { }

  function test_revert_registerSigner_reregistrationNotAllowed() public { }

  function test_registerSigner_noReregistration_notWearingRegisteredHat() public { }

  function test_addSigner_notOwner() public { }

  function test_addSigner_alreadyOwner() public { }

  function test_removeSigner() public { }

  function test_removeSigner_lastSigner() public { }

  function test_revert_removeSigner_notSigner() public { }
}

contract TransactionValidationInternals is WithHSGHarnessInstanceTest {
  function test_checkModuleTransaction_calltoNonSafeTarget() public { }

  function test_checkModuleTransaction_delegatecallToApprovedTarget() public { }

  function test_revert_checkModuleTransaction_delegatecallToUnapprovedTarget() public { }

  function test_revert_checkModuleTransaction_callToSafe() public { }

  function test_checkSafeState() public { }

  function test_revert_checkSafeState_removesHSGAsGuard() public { }

  function test_revert_checkSafeState_changesThreshold() public { }

  function test_revert_checkSafeState_changesOwners() public { }

  function test_revert_checkSafeState_changesFallbackHandler() public { }

  function test_revert_checkSafeState_addsModule() public { }

  function test_revert_checkSafeState_disablesHSGAsModule() public { }
}

contract InternalViews is WithHSGHarnessInstanceTest {
  function test_fuzz_getRequiredValidSignatures() public { }

  function test_getRequiredValidSignatures_absolute() public { }

  function test_getRequiredValidSignatures_proportional() public { }

  function test_getNewThreshold() public { }

  function test_getNewThreshold_exceedsOwnerCount() public { }
}
