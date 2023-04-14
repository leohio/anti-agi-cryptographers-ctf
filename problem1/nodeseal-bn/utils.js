import BN from "bn.js";
import { randomBytes } from "crypto";
import { bn2array, arraySize } from "./bn2array.js";

function typeCheckBN(plainBigNum) {
  if (!BN.isBN(plainBigNum)) {
    throw new Error("Type Error: the input is not BN type");
  }
}

export function LWEencrypt(encryptor, plainBigNum, encoder) {
  typeCheckBN(plainBigNum);
  const plainNumArray = bn2array(plainBigNum);

  const plainNumArrayEncode = encoder.encode(Uint32Array.from(plainNumArray));
  return encryptor.encrypt(plainNumArrayEncode);
}

export function LWEaddMatrix(
  evaluator,
  cipherTexMatrix1,
  cipherTexMatrix2,
  seal
) {
  var cipherTexArray = [];
  for (let i = 0; i < arraySize; i++) {
    let cipherText = seal.CipherText();
    evaluator.add(cipherTexMatrix1[i], cipherTexMatrix2[i], cipherText);
    cipherTexArray.push(cipherText);
  }
  return { typeinfo: "cipherTexArray", contents: cipherTexArray };
}

export function LWEsmul(evaluator, encoder, cipherTex1, plainTexBN, seal) {
  const plainArray = bn2array(plainTexBN);

  var cipherTexArray = [];
  for (let i = 0; i < arraySize; i++) {
    let array0 = [];
    for (let j = 0; j < arraySize; j++) {
      array0.push(plainArray[i]);
    }

    let plainTexArray = Uint32Array.from(array0);
    let plainTexArrayEncoded = encoder.encode(plainTexArray);

    let cipherText = seal.CipherText();
    evaluator.multiplyPlain(cipherTex1, plainTexArrayEncoded, cipherText);
    cipherTexArray.push(cipherText);
  }

  return { typeinfo: "cipherTextMetrix", contents: cipherTexArray };
}

export function decryptMatrixToBN(decryptor, matrix, encoder) {
  var bn0 = new BN(0);
  for (let i = 0; i < arraySize; i++) {
    let intArray0 = decryptor.decrypt(matrix[i]);
    let intArray = encoder.decode(intArray0);

    for (let j = 0; j < arraySize; j++) {
      let bn = new BN(intArray[j]);

      let bnMul = bn.mul(new BN("1".concat("00".repeat(i + j))));

      bn0 = bn0.add(bnMul);
    }
  }
  return bn0;
}

// Returns a hex string without 0x-prefix
export function BN2Hex(value) {
  let hex = value.toString("hex");
  if (hex.length % 2) {
    hex = "0" + hex;
  }

  return hex;
}

export function generateRandomBN() {
  const value = randomBytes(32);

  return new BN(value.toString("hex"), 16);
}
