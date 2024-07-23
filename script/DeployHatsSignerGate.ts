import { config as dotEnvConfig } from "dotenv";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";
import { Wallet, Contract } from "zksync-ethers";
import * as hre from "hardhat";

const HatsSignerGateFactory = require("../artifacts-zk/src/HatsSignerGateFactory.sol/HatsSignerGateFactory.json");

// Before executing a real deployment, be sure to set these values as appropriate for the environment being deployed
// to. The values used in the script at the time of deployment can be checked in along with the deployment artifacts
// produced by running the scripts.
const contractName = "HatsSignerGate";
const OWNER_HAT_ID = 1;
const SIGNER_HAT_ID = 2;
const MIN_THRESHOLD = 2;
const TARGET_THRESHOLD = 2;
const MAX_SIGNERS = 5;
const FACTORY_ADDRESS = "0xAa5ECbAE5D3874A5b0CFD1c24bd4E2c0Fb305c32"

async function main() {
  dotEnvConfig();

  const deployerPrivateKey = process.env.PRIVATE_KEY;
  if (!deployerPrivateKey) {
    throw "Please set PRIVATE_KEY in your .env file";
  }

  console.log("Deploying " + contractName + "...");

  const zkWallet = new Wallet(deployerPrivateKey);
  const deployer = new Deployer(hre, zkWallet);
  const hatsSignerGateFactory = await new Contract(FACTORY_ADDRESS, HatsSignerGateFactory.abi, deployer.zkWallet);

  const tx = await hatsSignerGateFactory.deployHatsSignerGateAndSafe(OWNER_HAT_ID, SIGNER_HAT_ID, MIN_THRESHOLD, TARGET_THRESHOLD, MAX_SIGNERS);
  const tr = await tx.wait();
	console.log("Hats signer gate deployed at " + tr.contractAddress)

}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
