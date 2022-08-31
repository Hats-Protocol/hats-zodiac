// SPDX-License-Identifier: CC0
pragma solidity >=0.8.13;

import "./HatsSignerGate.sol";
import "@gnosis.pm/safe-contracts/contracts/GnosisSafe.sol";
import "@gnosis.pm/safe-contracts/contracts/libraries/MultiSend.sol";
// import "@gnosis.pm/zodiac/contracts/factory/ModuleProxyFactory.sol";
import "@gnosis.pm/safe-contracts/contracts/proxies/GnosisSafeProxyFactory.sol";

contract HatsSignerGateFactory {
    address public hatsAddress;
    // address public immutable hatsSignerGatesingleton;
    address public immutable safeSingleton;

    // Library to use for EIP1271 compatability
    address public immutable gnosisFallbackLibrary;

    // Library to use for all safe transaction executions
    address public immutable gnosisMultisendLibrary;

    string public version;

    GnosisSafeProxyFactory public gnosisSafeProxyFactory;

    // ModuleProxyFactory moduleProxyFactory;

    // Track list and count of deployed Hats signer gates
    // address[] public hatsSignerGateList;

    // events

    // constructor
    // deploys HatsSignerGateFactory
    // arg: version
    // deploys HatsSignerGate and stores its address
    constructor(
        // address _hatsSignerGateSingleton,
        address _hatsAddress,
        address _safeSingleton,
        address _gnosisFallbackLibrary,
        address _gnosisMultisendLibrary,
        address _gnosisSafeProxyFactory,
        // address _moduleProxyFactory,
        string memory _version
    ) {
        // hatsSignerGateSingleton = _hatsSignerGateSingleton;
        hatsAddress = _hatsAddress;
        safeSingleton = _safeSingleton;
        gnosisFallbackLibrary = _gnosisFallbackLibrary;
        gnosisMultisendLibrary = _gnosisMultisendLibrary;
        gnosisSafeProxyFactory = GnosisSafeProxyFactory(
            _gnosisSafeProxyFactory
        );
        // moduleProxyFactory = ModuleProxyFactory(_moduleProxyFactory);
        version = _version;
    }

    // option 1: deploy a new Safe and signer gate, all wired up
    //
    // deploy new HatsSignerGate with given ownerHat, signerHat, and other params
    // call gnosis safe proxy factory to deploy a safe
    // sets HatsSignerGate as module and guard on the safe

    function deployHatsSignerGateAndSafe(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners,
        uint256 _saltNonce
    ) public returns (address, address) {
        // Deploy new safe but do not set it up yet
        address payable safe = payable(
            gnosisSafeProxyFactory.createProxy(
                safeSingleton,
                hex"00"
                // abi.encodePacked(_hatsSignerGate, _saltNonce) // QUESTION what is this for?
            )
        );

        // Deploy new hats signer gate
        address hsg = deployHatsSignerGate(
            _ownerHatId,
            _signersHatId,
            safe,
            _minThreshold,
            _targetThreshold,
            _maxSigners
        );

        // Generate delegate calls so the safe calls enableModule and setGuard on itself during setup
        bytes memory enableHSGModule = abi.encodeWithSignature(
            "enableModule(address)",
            hsg
        );
        bytes memory enableHSGModuleMultisend = abi.encodePacked(
            uint8(0), // 0 for call; 1 for delegatecall
            safe, // to
            uint256(0), // value
            uint256(enableHSGModule.length), // data length
            bytes(enableHSGModule) // data
        );

        bytes memory multisendAction = abi.encodeWithSignature(
            "multiSend(bytes)",
            enableHSGModuleMultisend
        );

        // Workaround for solidity dynamic memory array
        address[] memory owners = new address[](1);
        owners[0] = hsg;

        // Call setup on safe to enable our new module/guard and set it as only owner
        GnosisSafe(safe).setup(
            owners,
            1,
            gnosisMultisendLibrary,
            multisendAction, // set hsg as module and guard
            gnosisFallbackLibrary,
            address(0),
            0,
            payable(address(0))
        );

        // set HSG as a guard
        HatsSignerGate(hsg).setUp();

        return (hsg, safe);
    }

    //
    // option 2: deploy a new signer gate and attach it to an existing Safe
    // deploy new HatsSignerGate with given ownerHat, signerHat, and other params

    function deployHatsSignerGate(
        uint256 _ownerHatId,
        uint256 _signersHatId,
        address _safe, // Gnosis Safe that the signers will join
        uint256 _minThreshold,
        uint256 _targetThreshold,
        uint256 _maxSigners // add 1 to the number of signers you really want
    ) public returns (address) {
        HatsSignerGate hsg = new HatsSignerGate(
            _ownerHatId,
            _signersHatId,
            _safe,
            hatsAddress,
            _minThreshold,
            _targetThreshold,
            _maxSigners,
            version
        );

        return address(hsg);
    }
}
