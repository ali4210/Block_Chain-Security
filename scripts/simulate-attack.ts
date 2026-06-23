import hre from "hardhat";
import { parseEther } from "viem";

async function main() {
  const connection = await hre.network.connect();
  const { viem } = connection;
  const [deployer, attackerWallet] = await viem.getWalletClients();

  console.log("Deployer:", deployer.account.address);
  console.log("Attacker:", attackerWallet.account.address);

  const bank = await viem.deployContract("VulnerableBank");
  console.log("VulnerableBank deployed at:", bank.address);

  const attacker = await viem.deployContract("AttackerContract", [bank.address], {
    client: { wallet: attackerWallet },
  });
  console.log("AttackerContract deployed at:", attacker.address);

  await bank.write.deposit({
    account: deployer.account,
    value: parseEther("10"),
  });

  const beforeBank = await bank.read.getContractBalance();
  const beforeAttacker = await attacker.read.getContractBalance();

  console.log("Bank balance before attack:", beforeBank.toString());
  console.log("Attacker contract balance before attack:", beforeAttacker.toString());

  await attacker.write.attack({
    account: attackerWallet.account,
    value: parseEther("1"),
  });

  const afterBank = await bank.read.getContractBalance();
  const afterAttacker = await attacker.read.getContractBalance();

  console.log("Bank balance after attack:", afterBank.toString());
  console.log("Attacker contract balance after attack:", afterAttacker.toString());
}
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
