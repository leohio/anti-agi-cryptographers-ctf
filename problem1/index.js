import BN from "bn.js";
import { ethers } from "ethers";
import express from "express";
import SEAL from "node-seal/allows_wasm_node_umd.js";
import { EC } from "./lib/makek.js";
import {
  setupLWEDecryptor,
  generateRandomBN,
  BN2Hex,
} from "./nodeseal-bn/index.js";
import dotenv from "dotenv";
import { setupBobK, step2 } from "./lib/steps.js";
import { PrivateKey } from "eciesjs";

let seal;
let bobKey;
let challengeMsgPrefixForAlice;
const ec = new EC("secp256k1");

const app = express();

app.use(express.json());

// Health check
app.use(async (req, res, next) => {
  if (!seal) {
    seal = await SEAL();
  }
  if (!bobKey) {
    dotenv.config();
    const bobPrivKey = process.env.PRIVATE_KEY; // without prefix
    if (bobPrivKey) {
      console.log("Bob's private key was read from the .env file.");
      bobKey = ec.keyFromPrivate(bobPrivKey, "hex");
    } else {
      console.log("Bob's private key was chosen at random.");
      bobKey = ec.genKeyPair();
    }

    console.log("bobPubKey:", bobKey.getPublic().encode("hex"));
    const bobAddress = ethers.utils.computeAddress(
      "0x" + bobKey.getPublic().encode("hex", false)
    );
    console.log("bobAddress:", bobAddress);
  }
  if (!challengeMsgPrefixForAlice) {
    challengeMsgPrefixForAlice = generateRandomBN();
    console.log(
      "challengeMsgPrefixForAlice:",
      BN2Hex(challengeMsgPrefixForAlice)
    );
  }
  next();
});

app.get("/", (_req, res) => {
  res.json({ message: "hello" });
});

// Fetch a challenge for Alice
app.get("/challenge-alice", (req, res) => {
  const challengeMsgForAlice = ethers.utils.keccak256(
    "0x" + BN2Hex(challengeMsgPrefixForAlice) + req.query.alicePubKey
  );

  res.json({ challengeMsg: challengeMsgForAlice });
});

// Fetch Bob's public key
app.get("/bob-key", (_req, res) => {
  const bobPubKey = bobKey.getPublic();
  const encodedBobPubKey = bobPubKey.encode("hex");
  res.json({ bobPubKey: encodedBobPubKey });
});

// Execute setupBobK
app.post("/bob-k-value", async (req, res) => {
  const alicePubKey = req.body.aliceKp;
  if (typeof alicePubKey !== "string") {
    throw new Error("alicePubKey must be hex string without 0x-prefix");
  }
  const challengeMsgForAlice = ethers.utils.keccak256(
    "0x" + BN2Hex(challengeMsgPrefixForAlice) + alicePubKey
  );
  const eciesKeyPair = new PrivateKey(
    Buffer.from(BN2Hex(bobKey.getPrivate()), "hex")
  );
  const setupBobKData = setupBobK({
    ...req.body,
    challengeMsgForAlice,
    eciesKeyPair,
    bobKey,
  });

  res.json({ fromBob: setupBobKData.aliceView });
});

// Execute step2
app.post("/step2", async (req, res) => {
  const eciesKeyPair = new PrivateKey(
    Buffer.from(BN2Hex(bobKey.getPrivate()), "hex")
  );
  const step2Data = step2({ ...req.body, eciesKeyPair, bobKey }, seal);
  res.json({ fromBob: step2Data.aliceView });
});

export { app as bobalice };
