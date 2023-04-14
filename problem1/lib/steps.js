import BN from "bn.js";
import { encrypt, decrypt } from "eciesjs";
import {
  LWEencrypt,
  LWEsmul,
  decryptMatrixToBN,
  LWEaddMatrix,
  BN2Hex,
  setupLWEDecryptor,
  generateRandomBN,
} from "../nodeseal-bn/index.js";
import { EC } from "./makek.js";
import { getMultiSigAddress } from "./getMultisigAddressPoint.js";
import { recoverAddress } from "@ethersproject/transactions";
import { hexZeroPad, joinSignature } from "@ethersproject/bytes";

const ec = new EC("secp256k1");

const one = new BN(1);

export const setupAliceK = ({ challengeMsgFromBob }, message) => {
  const aliceK = ec.makeK(message);
  const encodedMessage = message.toString("hex");

  const aliceKpKeyPair = ec.keyFromPrivate(aliceK.k, "hex");
  const aliceKpSig = ec.sign(
    new BN(challengeMsgFromBob, "hex"),
    aliceKpKeyPair
  );
  const challengeMsgForBob = generateRandomBN();

  return {
    aliceView: { message, aliceK, challengeMsgForBob },
    bobView: {
      message: encodedMessage,
      aliceKp: aliceK.kp.encode("hex"),
      aliceKpSig,
      challengeMsgFromAlice: challengeMsgForBob.toString("hex"),
    },
  };
};

export const setupBobK = ({
  eciesKeyPair,
  bobKey,
  message,
  aliceKp: encodedAliceKp,
  aliceKpSig,
  challengeMsgForAlice,
  challengeMsgFromAlice,
}) => {
  const bobK = ec.makeK(message);
  const plaintext = Buffer.from(BN2Hex(bobK.k), "hex");
  const cipherTextBobK = encrypt(eciesKeyPair.publicKey.toHex(), plaintext);
  const bobPubKey = bobKey.getPublic();

  const aliceKp = ec.keyFromPublic(encodedAliceKp, "hex").getPublic();
  if (!ec.verify(challengeMsgForAlice, aliceKpSig, aliceKp)) {
    throw new Error("fail to verify Alice's K");
  }

  const bobKpKeyPair = ec.keyFromPrivate(bobK.k, "hex");
  const bobKpSig = ec.sign(challengeMsgFromAlice, bobKpKeyPair);
  return {
    aliceView: {
      bobPubKey: bobPubKey.encode("hex"),
      bobKp: bobK.kp.encode("hex"),
      bobKpSig,
      cipherTextBobK,
    },
    bobView: {},
  };
};

export const step1 = async ({
  setup,
  aliceKey,
  message: encodedMessage,
  aliceK,
  bobKp: encodedBobKp,
  cipherTextBobK,
  challengeMsgForBob,
  bobKpSig,
}) => {
  const message = new BN(encodedMessage, "hex");
  const bobKp = ec.curve.decodePoint(encodedBobKp, "hex");
  const multiKp = bobKp.mul(aliceK.k); // K = k1 k2 G
  const alicePrivKey = aliceKey.getPrivate();

  if (!ec.verify(challengeMsgForBob, bobKpSig, bobKp)) {
    throw new Error("fail to verify Bob's K");
  }

  const p0 = alicePrivKey
    .mul(multiKp.getX())
    .add(message)
    .mul(aliceK.kinv)
    .umod(ec.n); // p0 = (a1 * x + m) / k1
  const p1 = message.mul(aliceK.kinv).umod(ec.n); // p1 = m / k1

  const enc0 = await LWEencrypt(setup.encryptor, p0, setup.encoder);
  const enc1 = await LWEencrypt(setup.encryptor, p1, setup.encoder);

  const encodedLWEPublicKey = setup.encodedLWEPublicKey;

  return {
    aliceView: { multiKp, p0, p1 },
    bobView: {
      cipherTextBobK: Buffer.from(cipherTextBobK).toString("hex"),
      multiKp: multiKp.encode("hex"),
      enc0: enc0.save(),
      enc1: enc1.save(),
      encodedLWEPublicKey,
    },
  };
};

export const step2 = (
  {
    encodedLWEPublicKey,
    bobKey,
    eciesKeyPair,
    cipherTextBobK: encodedCipherTextBobK,
    enc0: encodedEnc0,
    enc1: encodedEnc1,
  },
  seal
) => {
  if (typeof encodedLWEPublicKey !== "string") {
    throw new Error("lwePublicKey must be string");
  }
  const setup = setupLWEDecryptor(seal, encodedLWEPublicKey);

  let enc0 = seal.CipherText();
  enc0.load(setup.context, encodedEnc0);

  let enc1 = seal.CipherText();
  enc1.load(setup.context, encodedEnc1);

  const cipherTextBobK = Buffer.from(encodedCipherTextBobK, "hex");
  const bobk = new BN(
    decrypt(eciesKeyPair.toHex(), cipherTextBobK).toString("hex"),
    "hex"
  );
  const bobkInv = bobk.invm(ec.n);
  const bobPrivKey = bobKey.getPrivate();
  const input0 = bobkInv.mul(bobPrivKey).umod(ec.n); // a2 / k2
  const input1 = bobkInv.mul(one.sub(bobPrivKey)).umod(ec.n); // (1 - a2) / k2
  const cipherText0 = LWEsmul(
    setup.evaluator,
    setup.encoder,
    enc0,
    input0,
    seal
  ); // c0 = Enc[ a2 (a1 * x + m) / k1 * k2 ]
  const cipherText1 = LWEsmul(
    setup.evaluator,
    setup.encoder,
    enc1,
    input1,
    seal
  ); // c1 = Enc[ m (1 - a2) / k1 * k2 ]

  const cipherText2 = LWEaddMatrix(
    setup.evaluator,
    cipherText0.contents,
    cipherText1.contents,
    seal
  ); // c2 = c0 + c1

  return {
    aliceView: {
      cipherText2: {
        typeinfo: cipherText2.typeinfo,
        contents: cipherText2.contents.map((cipherText) => {
          return cipherText.save();
        }),
      },
    },
    bobView: {},
  };
};

export const step3 = ({
  setup,
  aliceKey,
  message: encodedMessage,
  cipherText2: encodedCipherText2,
  multiKp: encodedMultiKp,
}) => {
  const cipherText2 = {
    typeinfo: encodedCipherText2.typeinfo,
    contents: encodedCipherText2.contents.map((encodedCipherText) => {
      let cipherText = setup.seal.CipherText();
      cipherText.load(setup.context, encodedCipherText);

      return cipherText;
    }),
  };
  const multiKp = ec.keyFromPublic(encodedMultiKp, "hex").getPublic();
  const s = decryptMatrixToBN(
    setup.decryptor,
    cipherText2.contents,
    setup.encoder
  ); // s = (m + a1 * a2 * x) / t1 * t2
  const signature = getSignature(multiKp, s.umod(ec.n));

  return {
    aliceView: { signature },
    bobView: {
      message: encodedMessage,
      signature,
      alicePubKey: aliceKey.getPublic().encode("hex"),
    },
  };
};

export const getFullSignatureForAlice = ({
  aliceKey,
  message: encodedMessage,
  signature,
  bobPubKey: encodedBobPubKey,
}) => {
  const message = new BN(encodedMessage, "hex");
  const bobPubKey = ec.keyFromPublic(encodedBobPubKey, "hex").getPublic();
  const address = getMultiSigAddress(aliceKey, bobPubKey);

  return {
    message,
    address,
    signature,
  };
};

export const getFullSignatureForBob = ({
  bobKey,
  message: encodedMessage,
  signature,
  alicePubKey: encodedAlicePubKey,
}) => {
  const message = new BN(encodedMessage, "hex");
  const alicePubKey = ec.keyFromPublic(encodedAlicePubKey, "hex").getPublic();
  const address = getMultiSigAddress(bobKey, alicePubKey);

  return {
    message,
    address,
    signature,
  };
};

export function recoverEncryptedMultiSig(message, address, signature) {
  const digest = message.toArray();
  const recoveredAddress = recoverAddress(digest, signature);

  return {
    validity: address === recoveredAddress,
    signature: joinSignature(signature),
  };
}

export function getSignature(multiK, s) {
  const n = ec.n;
  const nh = ec.n.ushrn(1);

  const kpX = multiK.getX();
  const r = kpX.umod(n);
  if (r.cmpn(0) === 0) {
    throw new Error("invalid signature");
  }

  let recoveryParam =
    (multiK.getY().isOdd() ? 1 : 0) | (multiK.getX().cmp(r) !== 0 ? 2 : 0);

  //  Use complement of `s`, if it is > `n / 2`
  if (s.cmp(nh) > 0) {
    s = n.sub(s);
    recoveryParam ^= 1;
  }
  const signature = {
    recoveryParam,
    r: multiK.getX(),
    s,
  };

  return {
    recoveryParam: signature.recoveryParam,
    r: hexZeroPad("0x" + signature.r.toString(16), 32),
    s: hexZeroPad("0x" + signature.s.toString(16), 32),
  };
}
