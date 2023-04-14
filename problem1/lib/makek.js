//this is a wrapper of EC function here
//https://github.com/indutny/elliptic/blob/master/lib/elliptic/ec/index.js

import elliptic from "elliptic";
import BN from "bn.js";
import HmacDRBG from "hmac-drbg";
export const EC = elliptic.ec;

// This function is making a random number 'k' (sometimes it's 's') in the ECDSA
EC.prototype.makeK = function makeK(msg) {
  // Zero-extend key to provide enough entropy
  msg = this._truncateToN(new BN(msg, 16));
  const bytes = this.n.byteLength();
  const bkey = this.genKeyPair().getPrivate().toArray("be", bytes);

  // Zero-extend nonce to have the same byte size as N
  const nonce = msg.toArray("be", bytes);

  // Instantiate Hmac_DRBG
  const drbg = new HmacDRBG({
    hash: this.hash,
    entropy: bkey,
    nonce: nonce,
    pers: this.pers,
    persEnc: this.persEnc || "utf8",
  });

  // Number of bytes to generate
  const ns1 = this.n.sub(new BN(1));

  let k = new BN(drbg.generate(this.n.byteLength()));
  k = this._truncateToN(k, true);
  // k <= 1 || k >= n - 1
  if (k.cmpn(1) <= 0 || k.cmp(ns1) >= 0) {
    throw new Error("k must be greater than 1 and less than (n - 1)");
  };

  const kp = this.g.mul(k);
  if (kp.isInfinity()) {
    throw new Error("");
  }

  const kpX = kp.getX();
  const r = kpX.umod(this.n);
  if (r.cmpn(0) === 0) {
    throw new Error("");
  };
  const kinv = k.invm(this.n);
  
  return { r, k, kinv, kp, n: this.n };
};
