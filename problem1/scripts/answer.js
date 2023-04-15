import fetch from 'node-fetch';
import BN from 'bn.js';
import { EC } from '../lib/makek.js';
import { encrypt } from 'eciesjs';
import { LWEsetup, LWEencrypt, decryptMatrixToBN } from '../nodeseal-bn/index.js';

// On step2, the server will accept:
//   - enc_B(k_B)
//   - enc0
//   - enc1
// where enc_B is an encryption function with Bob's key and k_B is a Bob's k and vice versa.
// And computes
//   enc0 * k_B^-1 * p_B + enc1 * k_B^-1 * (1 - p_B)
// where p_B is the Bob's private key.
// Thus, sending (enc_B(1), enc_A(1), enc_A(0)) directly returns Bob's private key.

export const main = async () => {
	// Prepare.
	const ec = new EC('secp256k1');
	const url = 'https://asia-northeast1-intmax.cloudfunctions.net/bobalice';
	// Fetch Bob's pubkey.
	const { bobPubKey } = await (await fetch(`${url}/bob-key`)).json();
	console.log(`Bob's pubkey: ${bobPubKey}`);
	// Prepare for step 2.
	const cipherTextBobK = encrypt(bobPubKey, Buffer.from('01', 'hex'));
	const setup = await LWEsetup();
	const enc0 = await LWEencrypt(setup.encryptor, new BN(1), setup.encoder);
	const enc1 = await LWEencrypt(setup.encryptor, new BN(0), setup.encoder);
	const body = {
		cipherTextBobK: cipherTextBobK.toString('hex'),
		enc0: enc0.save(),
		enc1: enc1.save(),
		encodedLWEPublicKey: setup.encodedLWEPublicKey,
	};
	const { fromBob: step2Data } = await (await fetch(`${url}/step2`, {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
		},
		body: JSON.stringify(body),
	})).json();
	const cipherText2 = {
		typeinfo: step2Data.cipherText2.typeinfo,
		contents: step2Data.cipherText2.contents.map((encodedCipherText) => {
			let cipherText = setup.seal.CipherText();
			cipherText.load(setup.context, encodedCipherText);
			return cipherText;
		}),
	};
	const s = decryptMatrixToBN(
		setup.decryptor,
		cipherText2.contents,
		setup.encoder
	); // s = (m + a1 * a2 * x) / t1 * t2
	console.log(s);
};

main();

// Solved first by Vis Virial (@visvirial).
