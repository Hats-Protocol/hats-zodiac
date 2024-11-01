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
  function test_happy_checkOwner() public { }

  function test_revert_checkOwner_notOwner() public { }

  function test_happy_checkUnlocked() public { }

  function test_revert_checkUnlocked_locked() public { }
}

contract OwnerSettingsInternals is WithHSGHarnessInstanceTest {
  function test_lock() public { }

  function test_setClaimableFor() public { }

  function test_setOwnerHat() public { }

  function test_addSignerHats() public { }

  function test_setDelegatecallTarget() public { }
  function test_setThresholdConfig() public { }

  function test_revert_setThresholdConfig_invalidMin() public { }

  function test_revert_setThresholdConfig_invalidAbsoluteTarget() public { }

  function test_revert_setThresholdConfig_invalidProportionalTarget() public { }

  function test_revert_setThresholdConfig_invalidThresholdType() public { }
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
}

contract TransactionValidationInternals is WithHSGHarnessInstanceTest {
  function test_checkModuleTransaction_calltoNonSafeTarget() public { }

  function test_checkModuleTransaction_delegatecallToApprovedTarget() public { }

  function test_revert_checkModuleTransaction_delegatecallToUnapprovedTarget() public { }

  function test_revert_checkModuleTransaction_callToSafe() public { }

  function test_checkSafeState() public { }

  function test_revert_checkSafeState_disablesGuard() public { }

  function test_revert_checkSafeState_changesThreshold() public { }

  function test_revert_checkSafeState_changesOwners() public { }

  function test_revert_checkSafeState_changesFallbackHandler() public { }

  function test_revert_checkSafeState_changesModules() public { }
}

contract InternalViews is WithHSGHarnessInstanceTest {
  function test_getRequiredValidSignatures() public { }

  function test_getNewThreshold() public { }
}
