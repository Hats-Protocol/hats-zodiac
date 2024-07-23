import { config as dotEnvConfig } from "dotenv";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";
import { Wallet } from "zksync-ethers";
import * as hre from "hardhat";

// Before executing a real deployment, be sure to set these values as appropriate for the environment being deployed
// to. The values used in the script at the time of deployment can be checked in along with the deployment artifacts
// produced by running the scripts.
const contractName = "HatsSignerGateFactory";
const HATS_ADDRESS = "0x32Ccb7600c10B4F7e678C7cbde199d98453D0e7e";
const SAFE_SIGNLETON = "0x1727c2c531cf966f902E5927b98490fDFb3b2b70";
const GNOSIS_FALLBACK_LIBRARY = "0x2f870a80647BbC554F3a0EBD093f11B4d2a7492A";
const GNOSIS_MULTISEND_LIBRARY = "0x0dFcccB95225ffB03c6FBB2559B530C2B7C8A912";
const GNOSIS_SAFE_PROXY = "0xDAec33641865E4651fB43181C6DB6f7232Ee91c2";
const VERSION = "0.6.0-zksync";

async function main() {
  dotEnvConfig();

  const deployerPrivateKey = process.env.PRIVATE_KEY;
  if (!deployerPrivateKey) {
    throw "Please set PRIVATE_KEY in your .env file";
  }

  console.log("Deploying " + contractName + "...");

  const zkWallet = new Wallet(deployerPrivateKey);
  const deployer = new Deployer(hre, zkWallet);

  const contract = await deployer.loadArtifact(contractName);
  const constructorArgs: any = [
    HATS_ADDRESS,
    SAFE_SIGNLETON,
    GNOSIS_FALLBACK_LIBRARY,
    GNOSIS_MULTISEND_LIBRARY,
    GNOSIS_SAFE_PROXY,
    VERSION,
  ];
  const hatsSignerGateFactory = await deployer.deploy(
    contract,
    constructorArgs,
    "create2",
    {
      customData: {
        salt: "0x0000000000000000000000000000000000000000000000000000000000004a75",
      },
    }
  );
  console.log(
    "constructor args:" +
      hatsSignerGateFactory.interface.encodeDeploy(constructorArgs)
  );
  console.log(
    `${contractName} was deployed to ${await hatsSignerGateFactory.getAddress()}`
  );
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
