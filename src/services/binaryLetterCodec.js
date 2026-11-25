const NIBBLE_TO_LETTER = Buffer.from('ABCDEFGHIKLMNOPQ', 'ascii');

const LETTER_TO_NIBBLE = new Int16Array(256).fill(-1);
for (let nibble = 0; nibble < NIBBLE_TO_LETTER.length; nibble += 1) {
  LETTER_TO_NIBBLE[NIBBLE_TO_LETTER[nibble]] = nibble;
}

export function isCodecLetter(byte) {
  return byte >= 0 && byte < 256 && LETTER_TO_NIBBLE[byte] !== -1;
}

export function encodeBytesToLetters(bytes) {
  const input = bytes instanceof Uint8Array ? bytes : Uint8Array.from(bytes);
  const output = Buffer.allocUnsafe(input.length * 2);
  for (let i = 0; i < input.length; i += 1) {
    const byte = input[i];
    output[i * 2] = NIBBLE_TO_LETTER[byte >> 4];
    output[i * 2 + 1] = NIBBLE_TO_LETTER[byte & 0x0f];
  }
  return output;
}

export function decodeLettersToBytes(letters) {
  const input = letters instanceof Uint8Array ? letters : Buffer.from(letters);
  if (input.length % 2 !== 0) {
    throw new Error('Jumlah huruf tidak genap');
  }
  const output = Buffer.allocUnsafe(input.length / 2);
  for (let i = 0; i < input.length; i += 2) {
    const high = LETTER_TO_NIBBLE[input[i]];
    const low = LETTER_TO_NIBBLE[input[i + 1]];
    if (high === -1 || low === -1) {
      throw new Error('Huruf di luar tabel pemetaan nibble');
    }
    output[i / 2] = (high << 4) | low;
  }
  return output;
}

export { NIBBLE_TO_LETTER };
