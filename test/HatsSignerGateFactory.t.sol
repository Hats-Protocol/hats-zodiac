// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "./HSGFactoryTestSetup.t.sol";

contract HatsSignerGateFactoryTest is HSGFactoryTestSetup {
    error NoOtherModulesAllowed();

    function setUp() public {
        version = "1.0";

        factory = new HatsSignerGateFactory(
            address(singletonHatsSignerGate),
            address(singletonMultiHatsSignerGate),
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
        assertEq(factory.multiHatsSignerGateSingleton(), address(singletonMultiHatsSignerGate));
        assertEq(address(factory.safeSingleton()), address(singletonSafe));
        assertEq(factory.gnosisFallbackLibrary(), gnosisFallbackLibrary);
        assertEq(factory.gnosisMultisendLibrary(), gnosisMultisendLibrary);
        assertEq(address(factory.gnosisSafeProxyFactory()), address(safeFactory));
    }

    function testDeployHatsSignerGate() public {
        ownerHat = uint256(1);
        signerHat = uint256(2);
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        hatsSignerGate = HatsSignerGate(
            factory.deployHatsSignerGate(ownerHat, signerHat, address(safe), minThreshold, targetThreshold, maxSigners)
        );

        assertEq(safe.getOwners()[0], address(this));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.ownerHat(), ownerHat);
        assertEq(hatsSignerGate.getHatsContract(), HATS);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);
    }

    function testDeployHatsSignersGateAndSafe(
        uint256 _ownerHat,
        uint256 _signerHat,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners
    ) public {
        vm.assume(_ownerHat > 0);
        ownerHat = _ownerHat;

        vm.assume(_signerHat > 0);
        signerHat = _signerHat;

        vm.assume(_maxSigners > 1);
        maxSigners = _maxSigners;

        vm.assume(_targetThreshold <= maxSigners);
        targetThreshold = _targetThreshold;

        vm.assume(_minThreshold <= targetThreshold);
        minThreshold = _minThreshold;

        (hatsSignerGate, safe) = deployHSGAndSafe(ownerHat, signerHat, minThreshold, targetThreshold, maxSigners);

        assertEq(safe.getOwners()[0], address(hatsSignerGate));

        assertEq(hatsSignerGate.minThreshold(), minThreshold);
        assertEq(hatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(hatsSignerGate.safe()), address(safe));
        assertEq(hatsSignerGate.maxSigners(), maxSigners);
        assertEq(hatsSignerGate.version(), version);

        assertTrue(safe.isModuleEnabled(address(hatsSignerGate)));

        assertEq(address(bytes20(vm.load(address(safe), GUARD_STORAGE_SLOT) << 96)), address(hatsSignerGate));

        assertEq(hatsSignerGate.ownerHat(), ownerHat);
        assertEq(hatsSignerGate.getHatsContract(), HATS);
    }

    function testCannotReinitializeHSGSingleton() public {
        bytes memory initializeParams =
            abi.encode(ownerHat, signerHat, address(safe), HATS, minThreshold, targetThreshold, maxSigners, version, 0);
        singletonHatsSignerGate.setUp(initializeParams);
        vm.expectRevert("Initializable: contract is already initialized");
        singletonHatsSignerGate.setUp(initializeParams);
    }

    function testDeployMultiHatsSignerGate() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        multiHatsSignerGate = MultiHatsSignerGate(
            factory.deployMultiHatsSignerGate(
                ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
            )
        );

        assertEq(safe.getOwners()[0], address(this));

        assertEq(multiHatsSignerGate.minThreshold(), minThreshold);
        assertEq(multiHatsSignerGate.ownerHat(), ownerHat);
        assertEq(multiHatsSignerGate.getHatsContract(), HATS);
        assertEq(multiHatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(multiHatsSignerGate.safe()), address(safe));
        assertEq(multiHatsSignerGate.maxSigners(), maxSigners);
        assertEq(multiHatsSignerGate.version(), version);
        assertTrue(multiHatsSignerGate.isValidSignerHat(2));
        assertFalse(multiHatsSignerGate.isValidSignerHat(3));
    }

    function testDeployHatsSignersGateAndSafe() public {
        ownerHat = 1;
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        (multiHatsSignerGate, safe) = deployMHSGAndSafe(ownerHat, signerHats, minThreshold, targetThreshold, maxSigners);

        assertEq(safe.getOwners()[0], address(multiHatsSignerGate));

        assertEq(multiHatsSignerGate.minThreshold(), minThreshold);
        assertEq(multiHatsSignerGate.targetThreshold(), targetThreshold);
        assertEq(address(multiHatsSignerGate.safe()), address(safe));
        assertEq(multiHatsSignerGate.maxSigners(), maxSigners);
        assertEq(multiHatsSignerGate.version(), version);
        assertTrue(multiHatsSignerGate.isValidSignerHat(2));
        assertFalse(multiHatsSignerGate.isValidSignerHat(3));

        assertTrue(safe.isModuleEnabled(address(multiHatsSignerGate)));

        assertEq(address(bytes20(vm.load(address(safe), GUARD_STORAGE_SLOT) << 96)), address(multiHatsSignerGate));

        assertEq(multiHatsSignerGate.ownerHat(), ownerHat);
        assertEq(multiHatsSignerGate.getHatsContract(), HATS);
    }

    function testCannotReinitializeMHSGSingleton() public {
        uint256[] memory signerHats = new uint256[](1);
        signerHats[0] = signerHat;

        bytes memory initializeParams =
            abi.encode(ownerHat, signerHats, address(safe), HATS, minThreshold, targetThreshold, maxSigners, version, 0);
        singletonMultiHatsSignerGate.setUp(initializeParams);
        vm.expectRevert("Initializable: contract is already initialized");
        singletonMultiHatsSignerGate.setUp(initializeParams);
    }

    function testCannotDeployHSGToSafeWithExistingModules() public {
        ownerHat = 1;
        signerHat = 2;
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
        factory.deployHatsSignerGate(ownerHat, signerHat, address(safe), minThreshold, targetThreshold, maxSigners);
    }

    function testCannotDeployMHSGToSafeWithExistingModules() public {
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
        factory.deployMultiHatsSignerGate(
            ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
        );
    }

    function testCanAttachHSGToSafeReturnsFalseWithModule() public {
        ownerHat = 1;
        signerHat = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        safe = deploySafe(initSafeOwners, 1);

        // deploy HSG
        address hsg =
            factory.deployHatsSignerGate(ownerHat, signerHat, address(safe), minThreshold, targetThreshold, maxSigners);

        // enable a module
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston
        executeSafeTxFrom(address(this), enableModuleData, safe);

        // canAttachHSGToSafe should return false
        assertFalse(factory.canAttachHSGToSafe(HatsSignerGate(hsg)));
    }

    function testCanAttachHSGToSafeReturnsFalseWithUnsafeSignerCounts() public {
        ownerHat = 1;
        signerHat = 2;
        minThreshold = 1;
        targetThreshold = 1;
        maxSigners = 2;

        // deploy a safe
        initSafeOwners[0] = address(this);
        mockIsWearerCall(address(this), signerHat, true);
        safe = deploySafe(initSafeOwners, 1);

        // deploy HSG
        HatsSignerGate hsg = HatsSignerGate(
            factory.deployHatsSignerGate(ownerHat, signerHat, address(safe), minThreshold, targetThreshold, maxSigners)
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
        assertFalse(
            factory.canAttachHSGToSafe(HatsSignerGate(hsg)), "should return false with validSignerCount > maxSigners"
        );
    }

    function testCanAttachHSGToSafeReturnsTrue() public {
        ownerHat = 1;
        signerHat = 2;
        minThreshold = 2;
        targetThreshold = 2;
        maxSigners = 5;

        // deploy a safe
        initSafeOwners[0] = address(this);
        mockIsWearerCall(address(this), signerHat, true);
        safe = deploySafe(initSafeOwners, 1);

        // deploy HSG
        address hsg =
            factory.deployHatsSignerGate(ownerHat, signerHat, address(safe), minThreshold, targetThreshold, maxSigners);

        // canAttachHSGToSafe should return true
        assertTrue(factory.canAttachHSGToSafe(HatsSignerGate(hsg)));
    }

    function testCanAttachMHSGToSafeReturnsFalseWithModule() public {
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

        // deploy MHSG
        address mhsg = factory.deployMultiHatsSignerGate(
            ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
        );

        // enable a module
        bytes memory enableModuleData = abi.encodeWithSignature("enableModule(address)", address(0xf00baa)); // some devs are from Boston
        executeSafeTxFrom(address(this), enableModuleData, safe);

        // canAttachHSGToSafe should return false
        assertFalse(factory.canAttachMHSGToSafe(MultiHatsSignerGate(mhsg)));
    }

    function testCanAttachMHSGToSafeReturnsFalseWithUnsafeSignerCounts() public {
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

        // deploy MHSG
        MultiHatsSignerGate mhsg = MultiHatsSignerGate(
            factory.deployMultiHatsSignerGate(
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
        assertEq(mhsg.validSignerCount(), 3, "valid signer count");
        assertEq(mhsg.maxSigners(), 2, "max signers");
        assertFalse(factory.canAttachMHSGToSafe(mhsg), "should return false with validSignerCount > maxSigners");
    }

    function testCanAttachMHSGToSafeReturnsTrue() public {
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

        // deploy MHSG
        address mhsg = factory.deployMultiHatsSignerGate(
            ownerHat, signerHats, address(safe), minThreshold, targetThreshold, maxSigners
        );

        // canAttachHSGToSafe should return true
        assertTrue(factory.canAttachMHSGToSafe(MultiHatsSignerGate(mhsg)));
    }
}
