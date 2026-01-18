const express = require('express');
const { Crypto } = require('@peculiar/webcrypto');
const app = express();
const crypto = new Crypto();

app.use(express.json({ limit: '50mb' }));

const DEFAULT_KEY = "Kawnew Encrypt On Top";

// --- Utilities ---
const strToBytes = (str) => new Uint8Array(Buffer.from(str, 'binary'));
const bytesToStr = (bytes) => Buffer.from(bytes).toString('binary');
const hexToStr = (hex) => Buffer.from(hex, 'hex').toString('utf8');
const b64_to_utf8 = (str) => Buffer.from(str, 'base64').toString('utf8');

function thaiBase64ToBytes(input) {
    const THAI_B64_CHARS = "กขฃคฅฆงจฉชซฌญฎฏฐฑฒณดตถทธนบปผฝพฟภมยรลวศษสหฬอฮ๐๑๒๓๔๕๖๗๘๙ะาเแโใไฤฦฯ";
    const THAI_B64_MAP = {};
    for (let i = 0; i < THAI_B64_CHARS.length; i++) THAI_B64_MAP[THAI_B64_CHARS[i]] = i;
    input = input.replace(/\s+/g, '');
    const bytes = [];
    for (let i = 0; i < input.length; i += 4) {
        const c1 = THAI_B64_MAP[input[i]], c2 = THAI_B64_MAP[input[i+1]];
        const c3 = i + 2 < input.length ? THAI_B64_MAP[input[i+2]] : null;
        const c4 = i + 3 < input.length ? THAI_B64_MAP[input[i+3]] : null;
        bytes.push((c1 << 2) | (c2 >> 4));
        if (c3 !== null) { bytes.push(((c2 & 15) << 4) | (c3 >> 2));
        if (c4 !== null) bytes.push(((c3 & 3) << 6) | c4); }
    }
    return new Uint8Array(bytes);
}

class ChaCha20 {
    constructor(k, n) {
        this.input = new Uint32Array(16);
        this.input.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574], 0);
        for (let i = 0; i < 8; i++) this.input[4+i] = (k[i*4]|(k[i*4+1]<<8)|(k[i*4+2]<<16)|(k[i*4+3]<<24))>>>0;
        this.input[12] = 1;
        for (let i = 0; i < 3; i++) this.input[13+i] = (n[i*4]|(n[i*4+1]<<8)|(n[i*4+2]<<16)|(n[i*4+3]<<24))>>>0;
    }
    quarterRound(x, a, b, c, d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d]<<16|x[d]>>>16)>>>0;
        x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b]<<12|x[b]>>>20)>>>0;
        x[a] += x[b]; x[d] ^= x[a]; x[d] = (x[d]<<8|x[d]>>>24)>>>0;
        x[c] += x[d]; x[b] ^= x[c]; x[b] = (x[b]<<7|x[b]>>>25)>>>0;
    }
    encrypt(data) {
        const out = new Uint8Array(data.length);
        for (let i = 0; i < data.length; i += 64) {
            const x = new Uint32Array(this.input);
            for (let k = 0; k < 10; k++) {
                this.quarterRound(x,0,4,8,12); this.quarterRound(x,1,5,9,13);
                this.quarterRound(x,2,6,10,14); this.quarterRound(x,3,7,11,15);
                this.quarterRound(x,0,5,10,15); this.quarterRound(x,1,6,11,12);
                this.quarterRound(x,2,7,8,13); this.quarterRound(x,3,4,9,14);
            }
            for (let j = 0; j < 16; j++) x[j] = (x[j] + this.input[j])>>>0;
            for (let j = 0; j < 64 && i+j < data.length; j++) {
                out[i+j] = data[i+j] ^ ((x[j>>2] >>> ((j&3)<<3)) & 0xff);
            }
            this.input[12]++;
        }
        return out;
    }
}

async function kawnewDecrypt(encryptedText, customKey = DEFAULT_KEY) {
    const rawBytes = encryptedText.split(/[\s,]+/).filter(t => /^0x[0-9a-fA-F]{1,2}$/.test(t)).map(t => parseInt(t, 16));
    let data = new Uint8Array(rawBytes);
    
    // VM Layer (Simple Version)
    if (data[0] === 0x4B && data[1] === 0x4E) {
        const OPS = { ADD: data[2], SUB: data[3], XOR: data[4], PUSH: data[5], FINISH: data[6] };
        let out = [], acc = 0, ptr = 7;
        while (ptr < data.length) {
            let op = data[ptr++]; if (op === OPS.FINISH) break;
            if (op === OPS.PUSH) acc = data[ptr++];
            else if (op === OPS.ADD) acc = (acc + data[ptr++]) & 0xFF;
            else if (op === OPS.SUB) acc = (acc - data[ptr++]) & 0xFF;
            else if (op === OPS.XOR) acc = acc ^ data[ptr++];
            if (ptr < data.length && (data[ptr] === OPS.PUSH || data[ptr] === OPS.FINISH)) out.push(acc);
        }
        data = new Uint8Array(out);
    }

    const nonce = data.slice(0, 12), cipher = data.slice(12);
    const kMat = await crypto.subtle.importKey("raw", new TextEncoder().encode(customKey), {name:"PBKDF2"}, false, ["deriveBits", "deriveKey"]);
    const ccKey = await crypto.subtle.deriveBits({name:"PBKDF2", salt:new Uint8Array(16), iterations:100000, hash:"SHA-256"}, kMat, 256);
    
    const decBytes = new ChaCha20(new Uint8Array(ccKey), nonce).encrypt(cipher);
    const packed = thaiBase64ToBytes(b64_to_utf8(bytesToStr(decBytes)));
    
    const salt = packed.slice(0, 16), iv = packed.slice(16, 28), aesData = packed.slice(28);
    const aesKey = await crypto.subtle.deriveKey({name:"PBKDF2", salt, iterations:50000, hash:"SHA-256"}, kMat, {name:"AES-GCM", length:256}, false, ["decrypt"]);
    
    const decrypted = await crypto.subtle.decrypt({name:"AES-GCM", iv}, aesKey, aesData);
    return hexToStr(new TextDecoder().decode(decrypted));
}

app.post('/decrypt', async (req, res) => {
    try {
        const result = await kawnewDecrypt(req.body.code, req.body.key || DEFAULT_KEY);
        res.json({ success: true, decryptedCode: result });
    } catch (e) {
        res.status(500).json({ success: false, error: e.message });
    }
});

app.listen(3000, () => console.log("Kawnew API Online!"));
