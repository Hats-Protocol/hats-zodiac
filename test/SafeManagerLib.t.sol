// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import { Test, console2 } from "forge-std/Test.sol";
import { TestSuite } from "./TestSuite.t.sol";
import { SafeManagerLib } from "../src/lib/SafeManagerLib.sol";
import { ISafe, IModuleManager, IGuardManager, IOwnerManager } from "../src/lib/safe-interfaces/ISafe.sol";
import { WithHSGInstanceTest, WithHSGHarnessInstanceTest } from "./TestSuite.t.sol";
import { HatsSignerGateHarness } from "./harnesses/HatsSignerGateHarness.sol";
import { ModuleProxyFactory } from "../lib/zodiac/contracts/factory/ModuleProxyFactory.sol";

contract SafeManagerLib_EncodingActions is Test {
  function test_fuzz_encodeEnableModuleAction(address _moduleToEnable) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeEnableModuleAction(_moduleToEnable);

    // Generate the expected encoded data manually
    bytes memory expectedData = abi.encodeWithSelector(IModuleManager.enableModule.selector, _moduleToEnable);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeDisableModuleAction(address _previousModule, address _moduleToDisable) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeDisableModuleAction(_previousModule, _moduleToDisable);

    // Generate the expected encoded data manually
    bytes memory expectedData =
      abi.encodeWithSelector(IModuleManager.disableModule.selector, _previousModule, _moduleToDisable);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeSetGuardAction(address _guardToSet) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeSetGuardAction(_guardToSet);

    // Generate the expected encoded data manually
    bytes memory expectedData = abi.encodeWithSelector(IGuardManager.setGuard.selector, _guardToSet);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeRemoveHSGAsGuardAction() public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeRemoveHSGAsGuardAction();

    // Generate the expected encoded data manually - setting guard to the zero address to remove it
    bytes memory expectedData = abi.encodeWithSelector(IGuardManager.setGuard.selector, address(0));

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeSwapOwnerAction(address _prevOwner, address _oldOwner, address _newOwner) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeSwapOwnerAction(_prevOwner, _oldOwner, _newOwner);

    // Generate the expected encoded data manually
    bytes memory expectedData =
      abi.encodeWithSelector(IOwnerManager.swapOwner.selector, _prevOwner, _oldOwner, _newOwner);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeRemoveOwnerAction(address _prevOwner, address _oldOwner, uint256 _newThreshold) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeRemoveOwnerAction(_prevOwner, _oldOwner, _newThreshold);

    // Generate the expected encoded data manually
    bytes memory expectedData =
      abi.encodeWithSelector(IOwnerManager.removeOwner.selector, _prevOwner, _oldOwner, _newThreshold);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeAddOwnerWithThresholdAction(address _owner, uint256 _newThreshold) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeAddOwnerWithThresholdAction(_owner, _newThreshold);

    // Generate the expected encoded data manually
    bytes memory expectedData =
      abi.encodeWithSelector(IOwnerManager.addOwnerWithThreshold.selector, _owner, _newThreshold);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }

  function test_fuzz_encodeChangeThresholdAction(uint256 _newThreshold) public pure {
    // Generate the encoded data using SafeManagerLib
    bytes memory encodedData = SafeManagerLib.encodeChangeThresholdAction(_newThreshold);

    // Generate the expected encoded data manually
    bytes memory expectedData = abi.encodeWithSelector(IOwnerManager.changeThreshold.selector, _newThreshold);

    // Assert the encoded data matches the expected data
    assertEq(encodedData, expectedData);
  }
}

contract SafeManagerLib_ExecutingActions is WithHSGHarnessInstanceTest {
  /// @dev Since execSafeTransactionFromHSG is called by all the other exec* functions, we rely on tests for those
  /// functions to verify that execSafeTransactionFromHSG is working correctly.

  function test_execDisableHSGAsOnlyModule() public {
    harness.execDisableHSGAsOnlyModule(safe);

    assertFalse(safe.isModuleEnabled(address(hatsSignerGate)), "hsg should no longer be a module");
  }

  function test_fuzz_execDisableHSGAsModule(uint256 _otherModulesCount) public {
    // bound the fuzzing parameters
    _otherModulesCount = bound(_otherModulesCount, 1, fuzzingAddresses.length - 1);

    address previousModule = fuzzingAddresses[0];

    // enable all the other modules
    vm.startPrank(address(safe));
    for (uint256 i = 0; i < _otherModulesCount; i++) {
      // enable the other modules
      safe.enableModule(fuzzingAddresses[i]);
    }
    vm.stopPrank();

    // disable the HatsSignerGate as a module; the previous module should always be the same reguardless of
    // how many other modules are enabled
    harness.execDisableHSGAsModule(safe, previousModule);

    assertFalse(safe.isModuleEnabled(address(harness)), "harness should no longer be a module");
  }

  function test_execRemoveHSGAsGuard() public {
    harness.execRemoveHSGAsGuard(safe);

    assertEq(SafeManagerLib.getSafeGuard(safe), address(0), "harness should no longer be a guard");
  }

  function test_execAttachNewHSG() public {
    // use a TestGuard as the new HSG, since it implements the necessary IERC165 interface
    address newHSG = address(tstGuard);

    harness.execAttachNewHSG(safe, newHSG);

    assertEq(SafeManagerLib.getSafeGuard(safe), newHSG, "newHSG should be the guard on the safe");
    assertTrue(safe.isModuleEnabled(newHSG), "newHSG should be a module on the safe");
    assertTrue(safe.isModuleEnabled(address(harness)), "harness should still be a module on the safe");
  }

  function test_fuzz_execChangeThreshold(uint256 _newThreshold) public {
    // bound the fuzzing parameter
    _newThreshold = bound(_newThreshold, 1, fuzzingAddresses.length);

    // add enough owners to the dummy safe to change the threshold
    // the threshold cannot be greater than the number of owners
    uint256 ownerCount = _newThreshold;
    vm.startPrank(address(safe));
    for (uint256 i; i < ownerCount; i++) {
      // add the owner with a constant threshold of 1
      safe.addOwnerWithThreshold(fuzzingAddresses[i], 1);
    }
    vm.stopPrank();

    // change the threshold
    harness.execChangeThreshold(safe, _newThreshold);

    assertEq(safe.getThreshold(), _newThreshold, "threshold should be updated");
  }

  function test_fuzz_fail_execChangeThreshold_tooHigh(uint256 _newThreshold) public {
    // bound the fuzzing parameter
    // the new threshold must be high enough to ensure that we can always make it greater than the owner count
    _newThreshold = bound(_newThreshold, 2, fuzzingAddresses.length);

    // add too few owners to the dummy safe to change the threshold
    // the threshold cannot be greater than the number of owners
    uint256 ownerCount = _newThreshold - 1 - 1; // we subtract an additional 1 to account for the existing initial owner
    vm.startPrank(address(safe));
    for (uint256 i; i < ownerCount; i++) {
      safe.addOwnerWithThreshold(fuzzingAddresses[i], 1);
    }
    vm.stopPrank();

    // attempt to change the threshold to a value greater than the number of owners
    // the transaction will not revert, but the threshold will not be updated
    harness.execChangeThreshold(safe, _newThreshold);

    assertEq(safe.getThreshold(), 1, "threshold should not be updated");
  }
}

contract SafeManagerLib_DeployingSafeAndAttachingHSG is TestSuite {
  function test_deploySafeAndAttachHSG() public {
    HatsSignerGateHarness harness = new HatsSignerGateHarness(
      address(hats), address(singletonSafe), safeFallbackLibrary, safeMultisendLibrary, address(safeFactory)
    );

    safe = ISafe(harness.deploySafeAndAttachHSG(
      address(safeFactory), address(singletonSafe), safeFallbackLibrary, safeMultisendLibrary
    ));

    assertTrue(safe.isModuleEnabled(address(harness)), "harness should be a module on the safe");
    assertEq(SafeManagerLib.getSafeGuard(safe), address(harness), "harness should be set as guard");
  }
}

contract SafeManagerLib_Views is WithHSGInstanceTest {
  function test_getSafeGuard() public view {
    assertEq(SafeManagerLib.getSafeGuard(safe), address(hatsSignerGate), "harness should be set as guard");
  }

  function test_getSafeFallbackHandler() public {
    assertEq(
      SafeManagerLib.getSafeFallbackHandler(safe),
      safeFallbackLibrary,
      "fallback handler should be the safeFallbackLibrary"
    );

    // iterate through fuzzingAddresses and test each
    vm.startPrank(address(safe));
    for (uint256 i; i < fuzzingAddresses.length; i++) {
      // set the fallback handler to the current address
      safe.setFallbackHandler(fuzzingAddresses[i]);

      assertEq(
        SafeManagerLib.getSafeFallbackHandler(safe),
        fuzzingAddresses[i],
        "fallback handler should be the current iteration's address"
      );
    }
    vm.stopPrank();
  }

  function test_getModulesWith1() public view {
    (address[] memory modulesWith1, address next) = SafeManagerLib.getModulesWith1(safe);

    assertEq(modulesWith1.length, 1, "there should be only one module");
    assertEq(modulesWith1[0], address(hatsSignerGate), "the only module should be the HatsSignerGate");
    assertEq(next, SafeManagerLib.SENTINELS, "the next pointer should be the sentinel");
  }

  function test_canAttachHSG_false() public view {
    assertFalse(
      SafeManagerLib.canAttachHSG(safe), "hatsSignerGate should not be able to attach, since it is already a module"
    );
  }

  function test_canAttachHSG_true() public {
    // deploy a new Safe with no owners and threshold of 1
    initSafeOwners[0] = address(this);
    ISafe freshSafe = _deploySafe(initSafeOwners, 1, TEST_SALT_NONCE);

    assertTrue(SafeManagerLib.canAttachHSG(freshSafe), "hatsSignerGate should be able to attach to freshSafe");
  }

  function test_findPrevOwner() public {
    address prevOwner = SafeManagerLib.findPrevOwner(safe.getOwners(), address(hatsSignerGate));
    assertEq(prevOwner, SENTINELS, "HSG's previous owner should be the sentinel");

    // add a bunch of owners to the safe and test each
    vm.startPrank(address(safe));
    address latestOwner = address(hatsSignerGate);
    for (uint256 i; i < fuzzingAddresses.length; i++) {
      address thisOwner = fuzzingAddresses[i];
      // add the new owner (no need to change the threshold)
      safe.addOwnerWithThreshold(thisOwner, 1);

      // check the previous owner for thisOwner
      prevOwner = SafeManagerLib.findPrevOwner(safe.getOwners(), thisOwner);
      // thisOwner's previous owner should always be the sentinel
      assertEq(prevOwner, SENTINELS, "wrong previous owner for thisOwner");

      // check the previous owner for the latestOwner
      if (i > 0) latestOwner = fuzzingAddresses[i - 1];
      prevOwner = SafeManagerLib.findPrevOwner(safe.getOwners(), latestOwner);
      // latestOwner's previous should be thisOwner
      assertEq(prevOwner, thisOwner, "wrong previous owner for latestOwner");
    }
    vm.stopPrank();
  }
}
