import hre from "hardhat";

async function main() {
  const connection = await hre.network.connect();
  const { viem } = connection;
  const [deployer] = await viem.getWalletClients();

  console.log("Deploying OpenZep_SecureBank with account:", deployer.account.address);

  const bank = await viem.deployContract("OpenZep_SecureBank");
  console.log("OpenZep_SecureBank deployed at:", bank.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
