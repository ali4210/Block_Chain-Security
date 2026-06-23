import hre from "hardhat";

async function main() {
  const connection = await hre.network.connect();
  const { viem } = connection;
  const [deployer] = await viem.getWalletClients();

  console.log("Deploying VulnerableBank with account:", deployer.account.address);

  const bank = await viem.deployContract("VulnerableBank");
  console.log("VulnerableBank deployed at:", bank.address);

  const attacker = await viem.deployContract("AttackerContract", [bank.address], {
    client: { wallet: deployer },
  });
  console.log("AttackerContract deployed at:", attacker.address);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
