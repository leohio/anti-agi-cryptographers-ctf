// Using this setting for big numbers. Avoiding the errors of transparency when some vectors are 0;
// Pls use this library for the calculations of enough big numbers
import SEAL from "node-seal/allows_wasm_node_umd.js";

export const LWEsetup = async () => {
  const seal = await SEAL();
  const context = setupLWE(seal);
  const keyGenerator = seal.KeyGenerator(context);

  const Secret_key_Keypair_A_ = keyGenerator.secretKey();
  const Public_key_Keypair_A_ = keyGenerator.createPublicKey();
  const encodedLWEPublicKey = Public_key_Keypair_A_.save();

  const evaluator = seal.Evaluator(context);
  const encoder = seal.BatchEncoder(context);

  const encryptor = seal.Encryptor(context, Public_key_Keypair_A_);
  const decryptor = seal.Decryptor(context, Secret_key_Keypair_A_);

  return {
    encryptor,
    decryptor,
    evaluator,
    encoder,
    seal,
    context,
    encodedLWEPublicKey,
  };
};

export const setupLWEDecryptor = (seal, encodedLWEPublicKey) => {
  const context = setupLWE(seal);
  let Public_key_Keypair_A_ = seal.PublicKey();
  Public_key_Keypair_A_.load(context, encodedLWEPublicKey);

  const evaluator = seal.Evaluator(context);
  const encoder = seal.BatchEncoder(context);
  const encryptor = seal.Encryptor(context, Public_key_Keypair_A_);

  return {
    encryptor,
    evaluator,
    encoder,
    seal,
    context,
  };
};

export const setupLWE = (seal) => {
  const schemeType = seal.SchemeType.bfv;
  const securityLevel = seal.SecurityLevel.tc128;
  const polyModulusDegree = 4096;
  const bitSizes = [36, 36, 37];
  const bitSize = 20;

  const encParams = seal.EncryptionParameters(schemeType);

  encParams.setPolyModulusDegree(polyModulusDegree);

  encParams.setCoeffModulus(
    seal.CoeffModulus.Create(polyModulusDegree, Int32Array.from(bitSizes))
  );

  encParams.setPlainModulus(
    seal.PlainModulus.Batching(polyModulusDegree, bitSize)
  );

  const context = seal.Context(encParams, true, securityLevel);

  if (!context.parametersSet()) {
    throw new Error(
      "Could not set the parameters in the given context. Please try different encryption parameters."
    );
  }

  return context;
};
