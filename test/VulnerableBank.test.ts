import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { network } from "hardhat";
import { parseEther } from "viem";

describe("VulnerableBank", async () => {
  it("should allow normal deposits and withdrawals", async () => {
    const { viem } = await network.connect();
    const [, user] = await viem.getWalletClients();

    const bank = await viem.deployContract("VulnerableBank");
    await bank.write.deposit({ account: user.account, value: parseEther("2") });

    const userBalanceInBank = await bank.read.balances([user.account.address]);
    assert.equal(userBalanceInBank, parseEther("2"));

    await bank.write.withdraw({ account: user.account });

    const remainingBalance = await bank.read.balances([user.account.address]);
    assert.equal(remainingBalance, 0n);
  });

  it("should be vulnerable to reentrancy attack", async () => {
    const { viem } = await network.connect();
    const [deployer, attacker] = await viem.getWalletClients();

    const bank = await viem.deployContract("VulnerableBank");

    const attackerContract = await viem.deployContract(
      "AttackerContract",
      [bank.address],
      {
        client: { wallet: attacker },
      }
    );

    await bank.write.deposit({ account: deployer.account, value: parseEther("10") });

    const bankBalanceBefore = await bank.read.getContractBalance();
    assert.equal(bankBalanceBefore, parseEther("10"));

    await attackerContract.write.attack({
      account: attacker.account,
      value: parseEther("1"),
    });

    const bankBalanceAfter = await bank.read.getContractBalance();
    const attackerLoot = await attackerContract.read.getContractBalance();

    assert.ok(bankBalanceAfter < parseEther("10"));
    assert.ok(attackerLoot > parseEther("1"));
  });

  it("should expose the unsafe emergencyDrain function", async () => {
    const { viem } = await network.connect();
    const [deployer, randomUser] = await viem.getWalletClients();

    const bank = await viem.deployContract("VulnerableBank");

    await bank.write.deposit({ account: deployer.account, value: parseEther("3") });

    const before = await bank.read.getContractBalance();
    assert.equal(before, parseEther("3"));

    await bank.write.emergencyDrain({ account: randomUser.account });

    const after = await bank.read.getContractBalance();
    assert.equal(after, 0n);
  });
});
