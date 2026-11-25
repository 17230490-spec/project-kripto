const ALPHABET = 'ABCDEFGHIKLMNOPQRSTUVWXYZ';
const FILLER = 'X'.charCodeAt(0);
const J_CODE = 'J'.charCodeAt(0);
const I_CODE = 'I'.charCodeAt(0);
const A_CODE = 'A'.charCodeAt(0);
const Z_CODE = 'Z'.charCodeAt(0);

function toBytes(input) {
  if (typeof input === 'string') return Buffer.from(input, 'ascii');
  if (input instanceof Uint8Array) return Buffer.from(input);
  throw new TypeError('Masukan Playfair harus Buffer/Uint8Array atau string ASCII');
}

export function normalizeKeyword(keyword) {
  const normalized = String(keyword ?? '')
    .toUpperCase()
    .replaceAll('J', 'I')
    .replace(/[^A-Z]/g, '');
  if (normalized.length === 0) {
    throw new Error('Kata kunci Playfair tidak boleh kosong');
  }
  return normalized;
}

export function buildSquare(keyword) {
  const normalized = normalizeKeyword(keyword);
  const used = new Int8Array(26);
  const letters = new Array(25);
  const fillSteps = [];
  let nextIndex = 0;

  const pushLetter = (letter, source, note = '') => {
    const index = letter.charCodeAt(0) - A_CODE;
    if (used[index]) {
      fillSteps.push({ letter, source, placed: false, note: note || 'duplikat, dilewati' });
      return;
    }
    used[index] = 1;
    const position = nextIndex;
    nextIndex += 1;
    letters[position] = letter;
    fillSteps.push({
      letter,
      source,
      placed: true,
      note,
      position: { row: Math.floor(position / 5), col: position % 5 },
    });
  };

  const rawKeyword = String(keyword).toUpperCase().replace(/[^A-Z]/g, '');
  for (const rawLetter of rawKeyword) {
    const letter = rawLetter === 'J' ? 'I' : rawLetter;
    pushLetter(letter, 'kata kunci', rawLetter === 'J' ? 'J digabung ke I' : '');
  }
  for (const letter of ALPHABET) {
    if (!used[letter.charCodeAt(0) - A_CODE]) pushLetter(letter, 'alfabet');
  }

  const matrix = [];
  for (let row = 0; row < 5; row += 1) {
    matrix.push(letters.slice(row * 5, row * 5 + 5));
  }

  const rows = new Int8Array(256).fill(-1);
  const cols = new Int8Array(256).fill(-1);
  for (let position = 0; position < letters.length; position += 1) {
    const code = letters[position].charCodeAt(0);
    rows[code] = Math.floor(position / 5);
    cols[code] = position % 5;
  }

  return {
    keyword: normalized,
    letters: letters.join(''),
    matrix,
    fillSteps,
    rows,
    cols,
  };
}

function validatePlaintextLetter(code) {
  if (code < A_CODE || code > Z_CODE || code === J_CODE || code === FILLER) {
    throw new Error('Masukan Playfair harus huruf A-Z tanpa J dan tanpa X');
  }
}

function validateCiphertextLetter(code, square) {
  if (code < A_CODE || code > Z_CODE || code === J_CODE || square.rows[code] === -1) {
    throw new Error('Ciphertext Playfair berisi huruf di luar matriks 5x5');
  }
}

function countEncryptPairs(bytes) {
  let pairs = 0;
  let index = 0;
  while (index < bytes.length) {
    const a = bytes[index];
    validatePlaintextLetter(a);
    if (index + 1 < bytes.length) {
      validatePlaintextLetter(bytes[index + 1]);
      index += bytes[index + 1] === a ? 1 : 2;
    } else {
      index += 1;
    }
    pairs += 1;
  }
  return pairs;
}

function ruleName(sameRow, sameCol) {
  if (sameRow) return 'baris sama';
  if (sameCol) return 'kolom sama';
  return 'persegi panjang';
}

function cryptPair(a, b, square, mode) {
  const rowA = square.rows[a];
  const colA = square.cols[a];
  const rowB = square.rows[b];
  const colB = square.cols[b];
  const delta = mode === 'encrypt' ? 1 : 4;

  let outRowA;
  let outColA;
  let outRowB;
  let outColB;

  if (rowA === rowB) {
    outRowA = rowA;
    outRowB = rowB;
    outColA = (colA + delta) % 5;
    outColB = (colB + delta) % 5;
  } else if (colA === colB) {
    outColA = colA;
    outColB = colB;
    outRowA = (rowA + delta) % 5;
    outRowB = (rowB + delta) % 5;
  } else {
    outRowA = rowA;
    outColA = colB;
    outRowB = rowB;
    outColB = colA;
  }

  const outA = square.letters.charCodeAt(outRowA * 5 + outColA);
  const outB = square.letters.charCodeAt(outRowB * 5 + outColB);

  return {
    outA,
    outB,
    rule: ruleName(rowA === rowB, colA === colB),
    aPos: { row: rowA, col: colA },
    bPos: { row: rowB, col: colB },
    aOutPos: { row: outRowA, col: outColA },
    bOutPos: { row: outRowB, col: outColB },
  };
}

function transform(input, keyword, mode, collectTrace) {
  const bytes = toBytes(input);
  const square = buildSquare(keyword);
  const trace = collectTrace
    ? { keyword: square.keyword, square: { matrix: square.matrix, letters: square.letters, fillSteps: square.fillSteps }, pairs: [] }
    : null;

  if (mode === 'decrypt') {
    if (bytes.length % 2 !== 0) {
      throw new Error('Jumlah huruf ciphertext Playfair harus genap');
    }
    for (const code of bytes) validateCiphertextLetter(code, square);
    const output = Buffer.allocUnsafe(bytes.length);
    for (let index = 0; index < bytes.length; index += 2) {
      const a = bytes[index];
      const b = bytes[index + 1];
      const result = cryptPair(a, b, square, mode);
      output[index] = result.outA;
      output[index + 1] = result.outB;
      if (trace) {
        trace.pairs.push({
          index: index / 2 + 1,
          input: String.fromCharCode(a, b),
          output: String.fromCharCode(result.outA, result.outB),
          inserted: false,
          rule: result.rule,
          aPos: result.aPos,
          bPos: result.bPos,
          aOutPos: result.aOutPos,
          bOutPos: result.bOutPos,
        });
      }
    }
    if (trace) {
      trace.padding = { isOdd: false, inserted: 0, totalInput: bytes.length };
      trace.output = output.toString('ascii');
      trace.stripped = stripFillerX(output).toString('ascii');
    }
    return { output, trace };
  }

  const pairCount = countEncryptPairs(bytes);
  const output = Buffer.allocUnsafe(pairCount * 2);
  let outIndex = 0;
  let index = 0;
  let inserted = 0;
  const isOdd = bytes.length % 2 === 1;

  while (index < bytes.length) {
    const a = bytes[index];
    let b;
    let pairInserted = false;
    let reason = '';

    if (index + 1 >= bytes.length) {
      b = FILLER;
      pairInserted = true;
      reason = 'jumlah huruf ganjil';
      index += 1;
    } else if (bytes[index + 1] === a) {
      b = FILLER;
      pairInserted = true;
      reason = 'huruf kembar disisipi X';
      index += 1;
    } else {
      b = bytes[index + 1];
      index += 2;
    }
    if (pairInserted) inserted += 1;

    const result = cryptPair(a, b, square, mode);
    output[outIndex] = result.outA;
    output[outIndex + 1] = result.outB;
    outIndex += 2;

    if (trace) {
      trace.pairs.push({
        index: trace.pairs.length + 1,
        input: String.fromCharCode(a, b),
        output: String.fromCharCode(result.outA, result.outB),
        inserted: pairInserted,
        insertReason: reason,
        rule: result.rule,
        aPos: result.aPos,
        bPos: result.bPos,
        aOutPos: result.aOutPos,
        bOutPos: result.bOutPos,
      });
    }
  }

  if (trace) {
    trace.padding = { isOdd, inserted, totalInput: bytes.length };
    trace.output = output.toString('ascii');
  }
  return { output, trace };
}

export function playfairEncrypt(input, keyword) {
  return transform(input, keyword, 'encrypt', false).output;
}

export function playfairDecrypt(input, keyword) {
  return transform(input, keyword, 'decrypt', false).output;
}

export function stripFillerX(input) {
  if (typeof input === 'string') return input.replaceAll('X', '');
  const bytes = toBytes(input);
  const output = Buffer.allocUnsafe(bytes.length);
  let length = 0;
  for (const code of bytes) {
    if (code !== FILLER) {
      output[length] = code;
      length += 1;
    }
  }
  return output.subarray(0, length);
}

function normalizeTraceText(text) {
  const original = String(text ?? '');
  const upper = original.toUpperCase();
  let normalized = '';
  const dropped = [];
  const steps = [];
  for (const letter of upper) {
    if (letter === 'J') {
      normalized += 'I';
      steps.push({ from: 'J', to: 'I', reason: 'J digabung ke I' });
    } else if (letter >= 'A' && letter <= 'Z') {
      normalized += letter;
    } else {
      dropped.push(letter);
    }
  }
  return { original, normalized, dropped, steps };
}

export function playfairEncryptTrace(text, keyword) {
  const normalization = normalizeTraceText(text);
  const { output, trace } = transform(Buffer.from(normalization.normalized, 'ascii'), keyword, 'encrypt', true);
  return {
    output: output.toString('ascii'),
    trace: { ...trace, normalization },
  };
}

export function playfairDecryptTrace(text, keyword) {
  const normalization = normalizeTraceText(text);
  const { output, trace } = transform(Buffer.from(normalization.normalized, 'ascii'), keyword, 'decrypt', true);
  return {
    output: output.toString('ascii'),
    trace: { ...trace, normalization },
  };
}
