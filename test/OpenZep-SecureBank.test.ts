import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { network } from "hardhat";
import { parseEther } from "viem";

describe("OpenZep_SecureBank", async () => {
  it("should allow normal deposits and withdrawals", async () => {
    const { viem } = await network.connect();
    const [, user] = await viem.getWalletClients();

    const bank = await viem.deployContract("OpenZep_SecureBank");
    await bank.write.deposit({ account: user.account, value: parseEther("2") });

    const userBalanceInBank = await bank.read.balances([user.account.address]);
    assert.equal(userBalanceInBank, parseEther("2"));

    await bank.write.withdraw([parseEther("1")], { account: user.account });

    const remainingBalance = await bank.read.balances([user.account.address]);
    assert.equal(remainingBalance, parseEther("1"));
  });

  it("should resist the reentrancy attack", async () => {
    const { viem } = await network.connect();
    const [deployer, attacker] = await viem.getWalletClients();

    const bank = await viem.deployContract("OpenZep_SecureBank");
    const attackerContract = await viem.deployContract("AttackerContract", [bank.address]);

    await bank.write.deposit({ account: deployer.account, value: parseEther("10") });

    let reverted = false;

    try {
      await attackerContract.write.attack({
        account: attacker.account,
        value: parseEther("1"),
      });
    } catch (error) {
      reverted = true;
    }

    assert.equal(reverted, true);

    const bankBalanceAfter = await bank.read.getContractBalance();
    assert.equal(bankBalanceAfter, parseEther("10"));
  });

  it("should restrict emergencyDrain to the owner", async () => {
    const { viem } = await network.connect();
    const [owner, randomUser] = await viem.getWalletClients();

    const bank = await viem.deployContract("OpenZep_SecureBank");

    await bank.write.deposit({ account: owner.account, value: parseEther("3") });

    let reverted = false;

    try {
      await bank.write.emergencyDrain({ account: randomUser.account });
    } catch (error) {
      reverted = true;
    }

    assert.equal(reverted, true);

    const balanceAfter = await bank.read.getContractBalance();
    assert.equal(balanceAfter, parseEther("3"));
  });
});
