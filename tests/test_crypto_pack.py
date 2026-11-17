"""The crypto starter pack: wallet keys and on-chain payments wait for a person once it's added from the dashboard.
From an EF founder's story (27 Oct 2026): a coding agent used wallet keys on a founder's machine to make a payment."""
import uuid

import pytest

from test_reported_bypasses import run  # noqa: F401
from test_server import BOSS, H, c, server  # noqa: F401
from test_team_features import shipped  # noqa: F401

PAY = 'const {ethers}=require("ethers");const w=new ethers.Wallet(process.env.PK,p);await w.sendTransaction({to,value});\n'


@pytest.fixture()
def crypto(c, shipped, tmp_path):
    assert c.post("/v1/policy/packs/crypto/apply", headers=BOSS).json()["ok"]
    ids = [x["id"] for x in server.policy.rules]
    assert ids.index("block-secret-files") < ids.index("crypto-wallet-keys") < ids.index("allow-reads")
    (tmp_path / "pay.js").write_text(PAY)
    return tmp_path


def tool(c, name, inp):
    return c.post("/v1/events", headers=H, json={"name": name, "source": "claude-code", "input": inp}).json()


@pytest.mark.parametrize("cmd", [
    "cast send 0xabc --value 1ether --private-key $PK",
    "bitcoin-cli -rpcwallet=main sendtoaddress bc1qxyz 0.5",
    "solana transfer 9xQabc 2 --allow-unfunded-recipient",
    "spl-token transfer MINT 100 9xQabc",
    "forge script script/Pay.s.sol --rpc-url $RPC --broadcast",
    "cat ~/.config/solana/id.json",
    "cat ~/.ethereum/keystore/UTC--2026-10-01T00-00-00Z--abc",
])
def test_signing_sending_and_key_reads_wait(c, crypto, cmd):
    assert run(c, crypto, [cmd])["decision"] == "review", cmd


@pytest.mark.parametrize("name,inp", [
    ("Read", {"file_path": "/home/u/.config/solana/id.json"}),
    ("Read", {"file_path": "/home/u/wallet.json"}),
    ("Read", {"file_path": "/home/u/notes/seed-phrase.txt"}),
    ("cdp.send_transaction", {"to": "0xabc", "value": "1"}),
    ("wallet.swap", {"from": "ETH", "to": "USDC", "amount": 2}),
    ("exchange.withdraw", {"asset": "BTC", "amount": 0.5}),
])
def test_wallet_reads_and_agent_tools_wait(c, crypto, name, inp):
    assert tool(c, name, inp)["decision"] == "review", name


@pytest.mark.parametrize("cmd", ["cast call 0xabc 'balanceOf(address)' 0xdef", "solana balance", "forge test",
                                 "npx hardhat compile", "node build.js", "cat src/wallet.ts"])
def test_everyday_crypto_dev_work_still_runs(c, crypto, cmd):
    (crypto / "build.js").write_text("console.log(1)\n")
    assert run(c, crypto, [cmd])["decision"] == "allow", cmd


def test_reads_of_code_still_run(c, crypto):
    assert tool(c, "Read", {"file_path": "/home/u/app/src/wallet.ts"})["decision"] == "allow"
    assert tool(c, "Read", {"file_path": "/home/u/app/src/mnemonic.ts"})["decision"] == "allow"


def test_payment_script_the_agent_wrote_waits_even_without_the_pack(c, tmp_path):
    # the founder's story: the agent writes the payment code and runs it in the same conversation
    s = str(uuid.uuid4())
    c.post("/v1/events", headers=H, json={"name": "Write", "source": "claude-code", "session_id": s, "output": "ok",
                                          "input": {"file_path": str(tmp_path / "pay.js"), "content": PAY}})
    (tmp_path / "pay.js").write_text(PAY)
    d = c.post("/v1/events", headers=H, json={"name": "Bash", "source": "claude-code", "session_id": s,
                                              "input": {"command": "node pay.js"}, "metadata": {"cwd": str(tmp_path)}})
    assert d.json()["decision"] == "review"
