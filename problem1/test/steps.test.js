import { LWEsetup, BN2Hex, generateRandomBN } from "../nodeseal-bn/index.js";
import { EC } from "../lib/makek.js";
import { PrivateKey } from "eciesjs";
import {
  getFullSignatureForAlice,
  getFullSignatureForBob,
  recoverEncryptedMultiSig,
  setupAliceK,
  setupBobK,
  step1,
  step2,
  step3,
} from "../lib/steps.js";

const ec = new EC("secp256k1");

describe("Two-Party ECDSA", async function () {
  it("makes a correct signature", async function () {
    let seal;

    // Alice
    const setup = await LWEsetup();
    seal = setup.seal;
    const aliceKey = ec.genKeyPair();

    const setupAliceData = {
      aliceView: { setup, aliceKey },
      bobView: {},
    };

    // Bob
    const bobKey = ec.genKeyPair();
    const bobPrivKey = bobKey.getPrivate();
    const eciesKeyPair = new PrivateKey(Buffer.from(BN2Hex(bobPrivKey), "hex"));
    const challengeMsgForAlice = generateRandomBN();
    const setupBobData = {
      aliceView: { challengeMsgFromBob: challengeMsgForAlice.toString("hex") },
      bobView: { bobKey, eciesKeyPair, challengeMsgForAlice },
    };

    // Alice
    const message = generateRandomBN();
    const setupAliceKData = setupAliceK(
      {
        ...setupAliceData.aliceView,
        ...setupBobData.aliceView,
      },
      message
    );

    setupAliceKData.bobView = JSON.parse(
      JSON.stringify(setupAliceKData.bobView)
    );

    // Bob
    const setupBobKData = setupBobK({
      ...setupBobData.bobView,
      ...setupAliceKData.bobView,
    });

    setupBobKData.aliceView = JSON.parse(
      JSON.stringify(setupBobKData.aliceView)
    );

    // Alice (step1)
    const step1Data = await step1({
      ...setupAliceData.aliceView,
      ...setupBobData.aliceView,
      ...setupAliceKData.aliceView,
      ...setupBobKData.aliceView,
    });

    step1Data.bobView = JSON.parse(JSON.stringify(step1Data.bobView));

    // Bob (step2)
    const step2Data = step2(
      {
        ...setupBobData.bobView,
        ...step1Data.bobView,
      },
      seal
    );

    step2Data.aliceView = JSON.parse(JSON.stringify(step2Data.aliceView));

    // Alice (step3)
    const step3Data = step3({
      ...setupAliceData.aliceView,
      ...setupBobData.aliceView,
      ...setupAliceKData.aliceView,
      ...setupBobKData.aliceView,
      ...step1Data.aliceView,
      ...step2Data.aliceView,
    });

    {
      const { message, address, signature } = getFullSignatureForAlice({
        ...setupAliceData.aliceView,
        ...setupBobData.aliceView,
        ...setupAliceKData.aliceView,
        ...setupBobKData.aliceView,
        ...step1Data.aliceView,
        ...step2Data.aliceView,
        ...step3Data.aliceView,
      });

      const { validity } = recoverEncryptedMultiSig(
        message,
        address,
        signature
      );

      if (!validity) {
        throw new Error("fail to verify multisig");
      }
    }

    // Bob
    {
      const { message, address, signature } = getFullSignatureForBob({
        ...setupBobData.bobView,
        ...step3Data.bobView,
      });

      const { validity } = recoverEncryptedMultiSig(
        message,
        address,
        signature
      );

      if (!validity) {
        throw new Error("fail to verify multisig");
      }
    }
  });
});
