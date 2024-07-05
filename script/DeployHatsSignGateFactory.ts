import { config as dotEnvConfig } from "dotenv";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";
import { Wallet } from "zksync-ethers";
import * as hre from "hardhat";

// Before executing a real deployment, be sure to set these values as appropriate for the environment being deployed
// to. The values used in the script at the time of deployment can be checked in along with the deployment artifacts
// produced by running the scripts.
const contractName = "HatsSignerGateFactory";
const HATS_ADDRESS = "0x32Ccb7600c10B4F7e678C7cbde199d98453D0e7e";
const SAFE_SIGNLETON = "";
const GNOSIS_FALLBACK_LIBRARY = "";
const GNOSIS_MULTISEND_LIBRARY = "";
const GNOSIS_SAFE_PROXY= "";

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
  const constructorArgs: any = [HATS_ADDRESS, SAFE_SIGNLETON, GNOSIS_FALLBACK_LIBRARY, GNOSIS_MULTISEND_LIBRARY, GNOSIS_SAFE_PROXY];
  const hatsSignerGateFactory = await deployer.deploy(contract, constructorArgs, "create2", {"customData": {"salt": "0x0000000000000000000000000000000000000000000000000000000000004a75"}});
  console.log("constructor args:" + hatsSignerGateFactory.interface.encodeDeploy(constructorArgs));
	console.log(`${contractName} was deployed to ${await hatsSignerGateFactory.getAddress()}`);
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
