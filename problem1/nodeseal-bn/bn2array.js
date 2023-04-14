export const arraySize = 60;

export function bn2array(bignum) {
  let numberArray = [];
  const interval = 2;
  let bignumString = bignum.toString();
  bignumString = "0"
    .repeat(arraySize * interval - bignumString.length)
    .concat(bignumString);
  for (let i = arraySize * interval; i - interval >= 0; i -= interval) {
    numberArray.push(parseInt(bignumString.slice(i - interval, i)));
  }
  return numberArray;
}
