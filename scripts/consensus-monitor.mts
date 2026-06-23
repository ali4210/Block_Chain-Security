import fs from "node:fs";
import path from "node:path";

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8545";
const OUTPUT_DIR = path.join(process.cwd(), "reports", "consensus");
const OUTPUT_FILE = path.join(OUTPUT_DIR, "consensus_status.json");

type GateLevel = "HIGH" | "MEDIUM" | "LOW" | "INFO";

type ConsensusStatus = {
  network: string;
  rpc_url: string;
  latest_block_number: number;
  latest_block_timestamp: number;
  now_timestamp: number;
  seconds_since_last_block: number;
  average_block_time_seconds?: number;
  health: GateLevel;
  details: string;
};

async function rpcCall(method: string, params: any[] = []): Promise<any> {
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method,
    params
  };

  const res = await fetch(RPC_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    throw new Error(`RPC error: HTTP ${res.status}`);
  }

  const json = await res.json();
  if (json.error) {
    throw new Error(`RPC error: ${JSON.stringify(json.error)}`);
  }

  return json.result;
}

function hexToNumber(hex: string | null | undefined): number {
  if (!hex) return 0;
  return Number(BigInt(hex));
}

function classifyHealth(secondsSinceLastBlock: number): { level: GateLevel; message: string } {
  if (secondsSinceLastBlock > 60) {
    return {
      level: "HIGH",
      message: `No new blocks for ${secondsSinceLastBlock.toFixed(
        0
      )} seconds. Chain may be stalled.`
    };
  }
  if (secondsSinceLastBlock > 30) {
    return {
      level: "MEDIUM",
      message: `Slow block production: last block ${secondsSinceLastBlock.toFixed(
        0
      )} seconds ago.`
    };
  }
  return {
    level: "INFO",
    message: `Block production is within expected range: last block ${secondsSinceLastBlock.toFixed(
      0
    )} seconds ago.`
  };
}

async function main() {
  try {
    if (!fs.existsSync(OUTPUT_DIR)) {
      fs.mkdirSync(OUTPUT_DIR, { recursive: true });
    }

    const [netVersion, latestBlockHex] = await Promise.all([
      rpcCall("net_version", []),
      rpcCall("eth_blockNumber", [])
    ]);

    const latestBlockNumber = hexToNumber(latestBlockHex);

    const latestBlock = await rpcCall("eth_getBlockByNumber", [
      latestBlockHex,
      false
    ]);

    const latestBlockTimestamp = hexToNumber(latestBlock?.timestamp);
    const nowSeconds = Math.floor(Date.now() / 1000);
    const secondsSinceLastBlock = Math.max(0, nowSeconds - latestBlockTimestamp);

    // Optional: simple average using previous block
    let averageBlockTimeSeconds: number | undefined = undefined;
    if (latestBlockNumber > 0) {
      const prevBlockHex = "0x" + (latestBlockNumber - 1).toString(16);
      const prevBlock = await rpcCall("eth_getBlockByNumber", [
        prevBlockHex,
        false
      ]);
      const prevTs = hexToNumber(prevBlock?.timestamp);
      if (prevTs > 0 && latestBlockTimestamp > prevTs) {
        averageBlockTimeSeconds = latestBlockTimestamp - prevTs;
      }
    }

    const healthSummary = classifyHealth(secondsSinceLastBlock);

    const status: ConsensusStatus = {
      network: String(netVersion),
      rpc_url: RPC_URL,
      latest_block_number: latestBlockNumber,
      latest_block_timestamp: latestBlockTimestamp,
      now_timestamp: nowSeconds,
      seconds_since_last_block: secondsSinceLastBlock,
      average_block_time_seconds: averageBlockTimeSeconds,
      health: healthSummary.level,
      details: healthSummary.message
    };

    fs.writeFileSync(OUTPUT_FILE, JSON.stringify(status, null, 2), "utf8");

    console.log(JSON.stringify(status, null, 2));
  } catch (error) {
    console.error(
      JSON.stringify(
        {
          error: "Consensus monitor failed",
          message: (error as Error).message
        },
        null,
        2
      )
    );
    process.exit(1);
  }
}

main();