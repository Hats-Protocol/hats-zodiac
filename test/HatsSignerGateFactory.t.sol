// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGFactoryTestSetup.t.sol";

contract HatsSignerGateFactoryTest is HSGFactoryTestSetup {
    error NoOtherModulesAllowed();

    function setUp() public {
        version = "1.0";

        factory = new HatsSignerGateFactory(
            address(singletonHatsSignerGate),
            HATS,
            address(singletonSafe),
            gnosisFallbackLibrary,
            gnosisMultisendLibrary,
            address(safeFactory),
            address(moduleProxyFactory),
            version
        );
    }

    function testDeployFactory() public {
        assertEq(factory.version(), version);
        assertEq(factory.hatsSignerGateSingleton(), address(singletonHatsSignerGate));
        assertEq(address(factory.safeSingleton()), address(singletonSafe));
        assertEq(factory.gnosisFallbackLibrary(), gnosisFallbackLibrary);
        assertEq(factory.gnosisMultisendLibrary(), gnosisMultisendLibrary);
        assertEq(address(factory.gnosisSafeProxyFactory()), address(safeFactory));
    }

    function testDeployHatsSignerGate() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        hatsSignerGate = HatsSignerGate(
            factory.deployHatsSignerGate(
                ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
            )
        );

        assertEq(safe.getOwners()[0], address(this));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.ownerHat(), ownerHat);
        assertEq(hatsSignerGate.getHatsContract(), HATS);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);
        assertTrue(hatsSignerGate.isValidSignerHat(2));
        assertFalse(hatsSignerGate.isValidSignerHat(3));
    }

    function testDeployHatsSignersGateAndSafe() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        (hatsSignerGate, safe) = deployHSGAndSafe(ownerHat, signerHats, minThreshold, targetThreshold, maxSigners);

        assertEq(safe.getOwners()[0], address(hatsSignerGate));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);
        assertTrue(hatsSignerGate.isValidSignerHat(2));
        assertFalse(hatsSignerGate.isValidSignerHat(3));

        assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));

        assertEq(address(bytes20(vm.load(address(safe), GUARD_STORAGE_SLOT) << 96)), address(hatsSignerGate));

        assertEq(hatsSignerGate.ownerHat(), ownerHat);
        assertEq(hatsSignerGate.getHatsContract(), HATS);
    }

    function testCannotReinitializeHSGSingleton() public {
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = signerHat;

        bytes memory initializeParams =
            abi.encode(ownerHat, signerHats, address(safe), HATS, minThreshold, targetThreshold, maxSigners, version, 0);
        vm.expectRevert("Initializable: contract is already initialized");
        singletonHatsSignerGate.setUp(initializeParams);
    }

    function testCannotDeployHSGToSafeWithExistingModules() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe to a signer
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        // add a module
        bytes memory addModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston
        executeSafeTxFrom(address(this), addModuleData, safe);

        // attempt to deploy HSG, should revert
        vm.expectRevert(NoOtherModulesAllowed.selector);
        factory.deployHatsSignerGate(
            ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
        );
    }

    function testCanAttachHSGToSafeReturnsFalseWithModule() public {
        ownerHat = 1;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;
        // create signerHats array
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        // deploy HSG
        address hsg = factory.deployHatsSignerGate(
            ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
        );

        // enable a module
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston
        executeSafeTxFrom(address(this), enableModuleData, safe);

        // canAttachHSGToSafe should return false
        assertFalse(factory.canAttachHSGToSafe(HatsSignerGate(hsg)));
    }

    function testCanAttachHSGToSafeReturnsFalseWithUnsafeSignerCounts() public {
        ownerHat = 1;
        minThreshold = 1;
        targetThreshold = 1;
        maxSigners = 2;
        // create signerHats array
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;

        // deploy a safe
        initSafeOwners[0] = address(this);
        mockIsWearerCall(address(this), signerHat, true);
        safe = deploySafe(initSafeOwners, 1);

        // deploy HSG
        HatsSignerGate hsg = HatsSignerGate(
            factory.deployHatsSignerGate(
                ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
            )
        );

        // add 2 owners and make them valid
        bytes memory addOwnerData = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", address(2), 1);
        executeSafeTxFrom(address(this), addOwnerData, safe);
        mockIsWearerCall(address(2), signerHat, true);

        addOwnerData = abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", address(3), 1);
        executeSafeTxFrom(address(this), addOwnerData, safe);
        mockIsWearerCall(address(3), signerHat, true);

        // canAttachHSGToSafe should return false
        assertEq(hsg.validSignerCount(), 3, "valid signer count");
        assertEq(hsg.maxSigners(), 2, "max signers");
        assertFalse(factory.canAttachHSGToSafe(hsg), "should return false with validSignerCount > maxSigners");
    }

    function testCanAttachHSGToSafeReturnsTrue() public {
        ownerHat = 1;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;
        // create signerHats array
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;

        // deploy a safe
        initSafeOwners[0] = address(this);
        mockIsWearerCall(address(this), signerHat, true);
        safe = deploySafe(initSafeOwners, 1);

        // deploy HSG
        address hsg = factory.deployHatsSignerGate(
            ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
        );

        // canAttachHSGToSafe should return true
        assertTrue(factory.canAttachHSGToSafe(HatsSignerGate(hsg)));
    }
}
