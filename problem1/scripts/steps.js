import { EC } from "../lib/makek.js";
import fetch from "node-fetch";
import { LWEsetup, generateRandomBN } from "../nodeseal-bn/index.js";
import {
  getFullSignatureForAlice,
  recoverEncryptedMultiSig,
  setupAliceK,
  step1,
  step3,
} from "../lib/steps.js";

const ec = new EC("secp256k1");
const url =
  process.env.SERVER_URL ||
  "https://asia-northeast1-intmax.cloudfunctions.net/bobalice";

const main = async () => {
  // Alice
  const setup = await LWEsetup();
  const aliceKey = ec.genKeyPair();

  const setupAliceData = {
    aliceView: { setup, aliceKey },
    bobView: {},
  };

  const encodedAlicePubKey = aliceKey.getPublic().encode("hex");
  const responseChallengeAlice = await fetch(
    url + `/challenge-alice?alicePubKey=${encodedAlicePubKey}`,
    {
      method: "GET",
      mode: "cors",
      cache: "no-cache",
      credentials: "same-origin",
      headers: {
        "Content-Type": "application/json",
      },
      redirect: "follow",
      referrerPolicy: "no-referrer",
    }
  );
  const { challengeMsgFromBob } = await responseChallengeAlice.json();

  // Alice
  const message = generateRandomBN();
  const setupAliceKData = setupAliceK(
    {
      ...setupAliceData.aliceView,
      challengeMsgFromBob,
    },
    message
  );

  // Bob
  const responseSetupBobKData = await fetch(url + "/bob-k-value", {
    method: "POST",
    mode: "cors",
    cache: "no-cache",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    redirect: "follow",
    referrerPolicy: "no-referrer",
    body: JSON.stringify(setupAliceKData.bobView),
  });
  const { fromBob: setupBobKData } = await responseSetupBobKData.json();

  // Alice (step1)
  const step1Data = await step1({
    ...setupAliceData.aliceView,
    ...setupAliceKData.aliceView,
    ...setupBobKData,
  });

  // Bob (step2)
  const responseStep2Data = await fetch(url + "/step2", {
    method: "POST",
    mode: "cors",
    cache: "no-cache",
    credentials: "same-origin",
    headers: {
      "Content-Type": "application/json",
    },
    redirect: "follow",
    referrerPolicy: "no-referrer",
    body: JSON.stringify(step1Data.bobView),
  });
  const { fromBob: step2Data } = await responseStep2Data.json();

  // Alice (step3)
  const step3Data = step3({
    ...setupAliceData.aliceView,
    ...setupAliceKData.aliceView,
    ...setupBobKData,
    ...step1Data.aliceView,
    ...step2Data,
  });

  {
    const { message, address, signature } = getFullSignatureForAlice({
      ...setupAliceData.aliceView,
      ...setupAliceKData.aliceView,
      ...setupBobKData,
      ...step1Data.aliceView,
      ...step2Data,
      ...step3Data.aliceView,
    });

    const { validity } = recoverEncryptedMultiSig(message, address, signature);

    if (!validity) {
      throw new Error("fail to verify multisig");
    }

    console.log("Done!");
  }
};

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
