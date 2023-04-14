import elliptic from "elliptic";
import { ethers } from "ethers";

var EC = elliptic.ec;
const ec = new EC("secp256k1");

export function getMultiSigAddress(keyPair, pubKey) {
  const multiP = ec
    .keyFromPublic(pubKey, "hex")
    .getPublic()
    .mul(keyPair.getPrivate());
  const multiSigAddress = ethers.utils.computeAddress(
    "0x" + multiP.encode("hex", false)
  );

  return multiSigAddress;
}
