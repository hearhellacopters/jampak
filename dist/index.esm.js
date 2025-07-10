import fs from 'fs';
import crypto from 'node:crypto';
import { BiWriter, BiReaderStream, BiReader, BiWriterStream } from 'bireader';
import zlib from 'zlib';
import { constants } from 'node:buffer';

const ciphers = crypto.getCiphers();
/**
 * Random Xor Shift RNG. Can seed with number, a Uint8Array or Buffer of 4 bytes
 * ```javascript
 * const seed; //number, Uint8Array or Buffer of 4 bytes
 * const rng = new RandomXorShift(seed);
 * const random_int = rng.random_int();
 * ```
 * @param {number|Uint8Array|Buffer} seed - Can seeded with a number or a Uint8Array or Buffer of 4 bytes
 */
class RandomXorShift {
    mt;
    constructor(seed) {
        var s;
        const mt = [0, 0, 0, 0];
        if (seed == undefined) {
            seed = new Date().getTime();
        }
        if (typeof Buffer !== 'undefined' && seed instanceof Buffer) {
            if (seed.length < 4) {
                throw new Error("Must be a seed Buffer of 4 bytes");
            }
            mt[0] = seed.readUInt32LE() >>> 0;
        }
        else {
            if (seed instanceof Uint8Array) {
                if (seed.length < 4) {
                    throw new Error("Must be a seed Uint8Array of 4 bytes");
                }
                mt[0] = ((seed[3] << 24) | (seed[2] << 16) | (seed[1] << 8) | seed[0]);
            }
            else {
                if (typeof seed == "number") {
                    mt[0] = seed >>> 0;
                }
            }
        }
        for (var i = 1; i < 5; i++) {
            s = mt[i - 1] ^ (mt[i - 1] >>> 30);
            mt[i] = (((((s & 0xffff0000) >>> 16) * 1812433253) << 16) + (s & 0x0000ffff) * 1812433253) + (i - 1);
            mt[i] >>>= 0;
        }
        mt.shift();
        var result = new Uint8Array(16);
        mt.forEach((e, i) => {
            result[(i * 4)] = e & 0xFF;
            result[(i * 4) + 1] = (e >> 8) & 0xFF;
            result[(i * 4) + 2] = (e >> 16) & 0xFF;
            result[(i * 4) + 3] = (e >> 24) & 0xFF;
        });
        this.mt = result;
    }
    /**
     * Generate a random unsigned 32 bit integer
     * @returns number
     */
    random_int() {
        let v1 = ((this.mt[3] << 24) | (this.mt[2] << 16) | (this.mt[1] << 8) | this.mt[0]);
        let v4 = ((this.mt[15] << 24) | (this.mt[14] << 16) | (this.mt[13] << 8) | this.mt[12]);
        let comp_1 = (v4 ^ (v4 >>> 19) ^ v1 ^ (v1 << 11) ^ ((v1 ^ (v1 << 11)) >>> 8)) >>> 0;
        let new_value = new Uint8Array(4);
        new_value[0] = comp_1 & 0xFF;
        new_value[1] = (comp_1 >> 8) & 0xFF;
        new_value[2] = (comp_1 >> 16) & 0xFF;
        new_value[3] = (comp_1 >> 24) & 0xFF;
        const shift = this.mt.subarray(4, 16);
        var newBuffer = new Uint8Array([...shift, ...new_value]);
        this.mt = newBuffer;
        return comp_1;
    }
}
class Crypt {
    keyBuff;
    ivBuffer;
    key;
    cipher = null;
    decipher = null;
    hashArray = ['aria-256-cbc', 'aes-256-cbc', 'camellia-256-cbc'];
    hash = "";
    useFallback = false;
    fallback = null;
    constructor(key) {
        if (key == 0 || key == undefined) {
            const rng = new RandomXorShift();
            this.key = rng.random_int();
        }
        else {
            this.key = key >>> 0;
        }
        const hash = this.key & 0x3;
        const spin = ((this.key >>> 2) & 0x3F) >>> 0;
        const value = ((this.key >>> 8) & 0xFFFFFF) >>> 0;
        const rng = new RandomXorShift(value);
        for (let i = 0; i < spin; i++)
            rng.random_int();
        const keyBuff = new BiWriter(Buffer.alloc(32));
        const iv = new BiWriter(Buffer.alloc(16));
        for (let i = 0; i < 8; i++) {
            keyBuff.uint32 = rng.random_int();
        }
        for (let i = 0; i < 4; i++) {
            iv.uint32 = rng.random_int();
        }
        this.hash = this.hashArray[hash % this.hashArray.length];
        if ((ciphers.findIndex((x) => x === this.hash) == -1)) {
            this.useFallback = true;
        }
        this.keyBuff = keyBuff.data;
        this.ivBuffer = iv.data;
    }
    ;
    fallbackCipher() {
        var crypt;
        switch (this.hash) {
            case "aes-256-cbc":
                crypt = new AES();
                break;
            case "aria-256-cbc":
                crypt = new ARIA();
                break;
            case "camellia-256-cbc":
                crypt = new CAMELLIA();
                break;
            default:
                throw new Error("Did not find cipher.");
        }
        crypt.set_key(this.keyBuff);
        crypt.set_iv(this.ivBuffer);
        this.fallback = crypt;
    }
    ;
    encrypt(data) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback.encrypt(data);
        }
        if (this.cipher == null) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return Buffer.concat([this.cipher.update(data), this.cipher.final()]);
    }
    ;
    decrypt(data) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback.decrypt(data);
        }
        if (this.decipher == null) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return Buffer.concat([this.decipher.update(data), this.decipher.final()]);
    }
    ;
    encrypt_block(data, final) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback.encrypt_block(data, final);
        }
        if (this.cipher == null) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.cipher.update(data);
    }
    ;
    decrypt_block(data, final) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback.decrypt_block(data, final);
        }
        if (this.decipher == null) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.decipher.update(data);
    }
    ;
    encrypt_final() {
        if (this.useFallback) {
            return Buffer.alloc(0);
        }
        if (this.cipher == null) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.cipher.final();
    }
    ;
    decrypt_final() {
        if (this.useFallback) {
            return Buffer.alloc(0);
        }
        if (this.decipher == null) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.decipher.final();
    }
    ;
}
const CRC_TABLE = new Int32Array([
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
]);
/**
 * Cyclic Redundancy Check 32.
 *
 * @param {Buffer} current - Message Buffer
 * @param {number?} previous - previous hash
 * @returns {number}
 */
function CRC32(current, previous) {
    if (!(current instanceof Buffer)) {
        throw new Error("Message must be a Buffer.");
    }
    let crc = previous === 0 ? 0 : ~~previous ^ -1;
    for (let index = 0; index < current.length; index++) {
        crc = CRC_TABLE[(crc ^ current[index]) & 0xff] ^ (crc >>> 8);
    }
    return crc ^ -1;
}
function xor(buf1, buf2) {
    let number = -1;
    for (let i = 0; i < buf1.length; i++) {
        const b = buf1[i];
        if (number != buf2.length - 1) {
            number = number + 1;
        }
        else {
            number = 0;
        }
        buf1[i] = b ^ buf2[number];
    }
    return buf1;
}
function align(a, n) {
    var a = a % n;
    if (a) {
        return (n - a);
    }
    else {
        return 0;
    }
}
function removePKCSPadding(buffer, number, PKCS = false) {
    const lastByte = buffer[buffer.length - 1];
    if (PKCS == true) {
        if (lastByte < 1 || lastByte > 17) {
            return buffer;
        }
        var len = buffer.length;
        var removed = 0;
        for (let i = buffer.length - 1; i > 0; i--) {
            if (buffer[i] == lastByte) {
                len--;
                removed++;
            }
        }
        if (removed == lastByte) {
            buffer = buffer.subarray(0, len);
        }
        return buffer;
    }
    else if (lastByte != number) {
        return buffer;
    }
    else {
        var len = buffer.length;
        for (let i = buffer.length - 1; i > 0; i--) {
            if (buffer[i] == number) {
                len--;
            }
        }
        return buffer.subarray(0, len);
    }
}
function extendBuffer(array, newLength, padValue) {
    const length = array.length;
    const to_padd = newLength - length;
    var paddbuffer = Buffer.alloc(to_padd, padValue);
    array = Buffer.concat([array, paddbuffer]);
    return array;
}
class AES {
    key;
    key_set = false;
    iv;
    iv_set = false;
    previous_block;
    AES_SubBytes(state, sbox) {
        for (var i = 0; i < 16; i++) {
            state[i] = sbox[state[i]];
        }
    }
    AES_AddRoundKey(state, rkey) {
        for (var i = 0; i < 16; i++) {
            state[i] ^= rkey[i];
        }
    }
    AES_ShiftRows(state, shifttab) {
        var h = new Array().concat(state);
        for (var i = 0; i < 16; i++) {
            state[i] = h[shifttab[i]];
        }
    }
    AES_MixColumns(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0], s1 = state[i + 1];
            var s2 = state[i + 2], s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            state[i + 0] ^= h ^ this.AES_xtime[s0 ^ s1];
            state[i + 1] ^= h ^ this.AES_xtime[s1 ^ s2];
            state[i + 2] ^= h ^ this.AES_xtime[s2 ^ s3];
            state[i + 3] ^= h ^ this.AES_xtime[s3 ^ s0];
        }
    }
    AES_MixColumns_Inv(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0], s1 = state[i + 1];
            var s2 = state[i + 2], s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            var xh = this.AES_xtime[h];
            var h1 = this.AES_xtime[this.AES_xtime[xh ^ s0 ^ s2]] ^ h;
            var h2 = this.AES_xtime[this.AES_xtime[xh ^ s1 ^ s3]] ^ h;
            state[i + 0] ^= h1 ^ this.AES_xtime[s0 ^ s1];
            state[i + 1] ^= h2 ^ this.AES_xtime[s1 ^ s2];
            state[i + 2] ^= h1 ^ this.AES_xtime[s2 ^ s3];
            state[i + 3] ^= h2 ^ this.AES_xtime[s3 ^ s0];
        }
    }
    AES_Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);
    AES_ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
    AES_Sbox_Inv = new Array(256);
    AES_xtime = new Array(256);
    AES_ShiftRowTab_Inv = new Array(16);
    constructor() {
    }
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer} key_data - ```Buffer```
     */
    set_key(key_data) {
        var kl = key_data.length, ks, Rcon = 1;
        switch (kl) {
            case 16:
                ks = 16 * (10 + 1);
                break;
            case 24:
                ks = 16 * (12 + 1);
                break;
            case 32:
                ks = 16 * (14 + 1);
                break;
            default:
                throw Error("Only key lengths of 16, 24 or 32 bytes allowed!");
        }
        const key = new Array(key_data.length);
        for (let i = 0; i < key_data.length; i++) {
            key[i] = key_data[i];
        }
        this.key = key;
        for (var i = kl; i < ks; i += 4) {
            var temp = key.slice(i - 4, i);
            if (i % kl == 0) {
                temp = new Array(this.AES_Sbox[temp[1]] ^ Rcon, this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]], this.AES_Sbox[temp[0]]);
                if ((Rcon <<= 1) >= 256)
                    Rcon ^= 0x11b;
            }
            else if ((kl > 24) && (i % kl == 16))
                temp = new Array(this.AES_Sbox[temp[0]], this.AES_Sbox[temp[1]], this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]]);
            for (var j = 0; j < 4; j++)
                key[i + j] = key[i + j - kl] ^ temp[j];
        }
        this.key_set = true;
        //setup
        for (var z = 0; z < 256; z++) {
            this.AES_Sbox_Inv[this.AES_Sbox[z]] = z;
        }
        for (var z = 0; z < 16; z++) {
            this.AES_ShiftRowTab_Inv[this.AES_ShiftRowTab[z]] = z;
        }
        for (var z = 0; z < 128; z++) {
            this.AES_xtime[z] = z << 1;
            this.AES_xtime[128 + z] = (z << 1) ^ 0x1b;
        }
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer} iv - ```Buffer```
     */
    set_iv(iv) {
        if (iv) {
            if (iv.length != 16) {
                throw Error("Enter a vaild 16 byte IV for CBC mode");
            }
            else {
                this.iv = iv;
                this.iv_set = true;
            }
        }
        else {
            throw Error("Enter a vaild 16 byte IV for CBC mode");
        }
    }
    ;
    encrypt_block(start_chunk, last_block) {
        //check if IV is set, if so runs CBC
        let block = start_chunk;
        if (last_block) {
            block = this.padd_block(start_chunk);
        }
        if (this.iv_set == true) {
            block = xor(block, this.iv);
        }
        const block_data = new Array(16);
        for (let i = 0; i < 16; i++) {
            block_data[i] = block[i];
        }
        var key = this.key;
        var l = key.length;
        this.AES_AddRoundKey(block_data, key.slice(0, 16));
        for (var i = 16; i < l - 16; i += 16) {
            this.AES_SubBytes(block_data, this.AES_Sbox);
            this.AES_ShiftRows(block_data, this.AES_ShiftRowTab);
            this.AES_MixColumns(block_data);
            this.AES_AddRoundKey(block_data, key.slice(i, i + 16));
        }
        this.AES_SubBytes(block_data, this.AES_Sbox);
        this.AES_ShiftRows(block_data, this.AES_ShiftRowTab);
        this.AES_AddRoundKey(block_data, key.slice(i, l));
        var block_out = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
            block_out[i] = block_data[i];
        }
        if (this.iv_set == true) {
            this.iv = block_out;
        }
        return block_out;
    }
    ;
    decrypt_block(start_chunk, last_block) {
        let block = start_chunk;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = block;
        const block_data = new Array(16);
        for (let i = 0; i < 16; i++) {
            block_data[i] = block[i];
        }
        var key = this.key;
        var l = key.length;
        this.AES_AddRoundKey(block_data, key.slice(l - 16, l));
        this.AES_ShiftRows(block_data, this.AES_ShiftRowTab_Inv);
        this.AES_SubBytes(block_data, this.AES_Sbox_Inv);
        for (var i = l - 32; i >= 16; i -= 16) {
            this.AES_AddRoundKey(block_data, key.slice(i, i + 16));
            this.AES_MixColumns_Inv(block_data);
            this.AES_ShiftRows(block_data, this.AES_ShiftRowTab_Inv);
            this.AES_SubBytes(block_data, this.AES_Sbox_Inv);
        }
        this.AES_AddRoundKey(block_data, key.slice(0, 16));
        var block_out = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
            block_out[i] = block_data[i];
        }
        var return_buffer = block_out;
        if (this.iv_set == true) {
            return_buffer = xor(block_out, this.iv);
        }
        if (last_block) {
            var padd_value = align(return_buffer.length, 16);
            return removePKCSPadding(return_buffer, padd_value, true);
        }
        return return_buffer;
    }
    ;
    padd_block(data) {
        const block_size = 16;
        if (data.length % block_size != 0) {
            var padd_value = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(padd_value, padd_value & 0xFF);
            data = Buffer.concat([data, paddbuffer]);
        }
        return data;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer```
     */
    encrypt(data_in, padding = 0) {
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer} data_in - `Buffer`
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns `Buffer`
     */
    decrypt(data_in, remove_padding = true) {
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            var return_block = this.decrypt_block(block);
            if ((remove_padding != false) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
class ARIA {
    key;
    key_set = false;
    iv;
    iv_set = false;
    previous_block;
    C1;
    C2;
    C3;
    SB1;
    SB2;
    SB3;
    SB4;
    mEK;
    mDK;
    mNumberRounds;
    mKeyLength;
    constructor() {
    }
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer} key - ```Buffer```
     */
    set_key(key) {
        if (this.mEK === undefined) {
            this.mEK = null;
        }
        if (this.mDK === undefined) {
            this.mDK = null;
        }
        if (this.mNumberRounds === undefined) {
            this.mNumberRounds = 0;
        }
        if (this.mKeyLength === undefined) {
            this.mKeyLength = 0;
        }
        this.scheduleKey(key);
        this.key_set = true;
    }
    /**
     * IV for CBC encryption.
     *
     * Must be same length as key!
     *
     * @param {Buffer} iv - ```Buffer```
     */
    set_iv(iv) {
        if (this.key_set != true) {
            throw Error("Must set key before IV");
        }
        if (iv) {
            //if (iv.length != this.mKeyLength) {
            //    throw Error(`Enter a vaild ${this.mKeyLength} byte IV for CBC mode`);
            //} else {
            this.iv = iv;
            this.iv_set = true;
            //}
        }
        else {
            throw Error(`Enter a vaild ${this.mKeyLength} byte IV for CBC mode`);
        }
    }
    ;
    C1_$LI$() {
        if (this.C1 == null) {
            this.C1 = Buffer.from([81, 124, 193, 183, 39, 34, 10, 148, 254, 19, 171, 232, 250, 154, 110, 224]);
        }
        return this.C1;
    }
    ;
    C2_$LI$() {
        if (this.C2 == null) {
            this.C2 = Buffer.from([109, 177, 74, 204, 158, 33, 200, 32, 255, 40, 177, 213, 239, 93, 226, 176]);
        }
        return this.C2;
    }
    ;
    C3_$LI$() {
        if (this.C3 == null) {
            this.C3 = Buffer.from([219, 146, 55, 29, 33, 38, 233, 112, 3, 36, 151, 117, 4, 232, 201, 14]);
        }
        return this.C3;
    }
    ;
    SB1_$LI$() {
        if (this.SB1 == null) {
            this.SB1 = Buffer.from([99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118,
                202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
                183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21,
                4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117,
                9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132,
                83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207,
                208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168,
                81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210,
                205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115,
                96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219,
                224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121,
                231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8,
                186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138,
                112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158,
                225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223,
                140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]);
        }
        return this.SB1;
    }
    ;
    SB2_$LI$() {
        if (this.SB2 == null) {
            this.SB2 = Buffer.from([226, 78, 84, 252, 148, 194, 74, 204, 98, 13, 106, 70, 60, 77, 139, 209,
                94, 250, 100, 203, 180, 151, 190, 43, 188, 119, 46, 3, 211, 25, 89, 193,
                29, 6, 65, 107, 85, 240, 153, 105, 234, 156, 24, 174, 99, 223, 231, 187,
                0, 115, 102, 251, 150, 76, 133, 228, 58, 9, 69, 170, 15, 238, 16, 235,
                45, 127, 244, 41, 172, 207, 173, 145, 141, 120, 200, 149, 249, 47, 206, 205,
                8, 122, 136, 56, 92, 131, 42, 40, 71, 219, 184, 199, 147, 164, 18, 83,
                255, 135, 14, 49, 54, 33, 88, 72, 1, 142, 55, 116, 50, 202, 233, 177,
                183, 171, 12, 215, 196, 86, 66, 38, 7, 152, 96, 217, 182, 185, 17, 64,
                236, 32, 140, 189, 160, 201, 132, 4, 73, 35, 241, 79, 80, 31, 19, 220,
                216, 192, 158, 87, 227, 195, 123, 101, 59, 2, 143, 62, 232, 37, 146, 229,
                21, 221, 253, 23, 169, 191, 212, 154, 126, 197, 57, 103, 254, 118, 157, 67,
                167, 225, 208, 245, 104, 242, 27, 52, 112, 5, 163, 138, 213, 121, 134, 168,
                48, 198, 81, 75, 30, 166, 39, 246, 53, 210, 110, 36, 22, 130, 95, 218,
                230, 117, 162, 239, 44, 178, 28, 159, 93, 111, 128, 10, 114, 68, 155, 108,
                144, 11, 91, 51, 125, 90, 82, 243, 97, 161, 247, 176, 214, 63, 124, 109,
                237, 20, 224, 165, 61, 34, 179, 248, 137, 222, 113, 26, 175, 186, 181, 129]);
        }
        return this.SB2;
    }
    ;
    SB3_$LI$() {
        if (this.SB3 == null) {
            this.SB3 = Buffer.from([82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
                124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
                84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
                8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
                114, 248, 246, 100, 134, 104, 152, 22, 212, 164, 92, 204, 93, 101, 182, 146,
                108, 112, 72, 80, 253, 237, 185, 218, 94, 21, 70, 87, 167, 141, 157, 132,
                144, 216, 171, 0, 140, 188, 211, 10, 247, 228, 88, 5, 184, 179, 69, 6,
                208, 44, 30, 143, 202, 63, 15, 2, 193, 175, 189, 3, 1, 19, 138, 107,
                58, 145, 17, 65, 79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
                150, 172, 116, 34, 231, 173, 53, 133, 226, 249, 55, 232, 28, 117, 223, 110,
                71, 241, 26, 113, 29, 41, 197, 137, 111, 183, 98, 14, 170, 24, 190, 27,
                252, 86, 62, 75, 198, 210, 121, 32, 154, 219, 192, 254, 120, 205, 90, 244,
                31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
                96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
                160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
                23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125]);
        }
        return this.SB3;
    }
    ;
    SB4_$LI$() {
        if (this.SB4 == null) {
            this.SB4 = Buffer.from([48, 104, 153, 27, 135, 185, 33, 120, 80, 57, 219, 225, 114, 9, 98, 60,
                62, 126, 94, 142, 241, 160, 204, 163, 42, 29, 251, 182, 214, 32, 196, 141,
                129, 101, 245, 137, 203, 157, 119, 198, 87, 67, 86, 23, 212, 64, 26, 77,
                192, 99, 108, 227, 183, 200, 100, 106, 83, 170, 56, 152, 12, 244, 155, 237,
                127, 34, 118, 175, 221, 58, 11, 88, 103, 136, 6, 195, 53, 13, 1, 139,
                140, 194, 230, 95, 2, 36, 117, 147, 102, 30, 229, 226, 84, 216, 16, 206,
                122, 232, 8, 44, 18, 151, 50, 171, 180, 39, 10, 35, 223, 239, 202, 217,
                184, 250, 220, 49, 107, 209, 173, 25, 73, 189, 81, 150, 238, 228, 168, 65,
                218, 255, 205, 85, 134, 54, 190, 97, 82, 248, 187, 14, 130, 72, 105, 154,
                224, 71, 158, 92, 4, 75, 52, 21, 121, 38, 167, 222, 41, 174, 146, 215,
                132, 233, 210, 186, 93, 243, 197, 176, 191, 164, 59, 113, 68, 70, 43, 252,
                235, 111, 213, 246, 20, 254, 124, 112, 90, 125, 253, 47, 24, 131, 22, 165,
                145, 31, 5, 149, 116, 169, 193, 91, 74, 133, 109, 19, 7, 79, 78, 69,
                178, 15, 201, 28, 166, 188, 236, 115, 144, 123, 207, 89, 143, 161, 249, 45,
                242, 177, 0, 148, 55, 159, 208, 46, 156, 110, 40, 63, 128, 240, 61, 211,
                37, 138, 181, 231, 66, 179, 199, 234, 247, 76, 17, 51, 3, 162, 172, 96]);
        }
        return this.SB4;
    }
    ;
    XOR(x, y) {
        var length = x.length;
        var result = Buffer.alloc(length);
        result.set(x);
        var i = 0;
        while ((i < length && i < y.length)) {
            {
                result[i] ^= y[i];
                i++;
            }
        }
        return result;
    }
    ;
    ROL(array, nShift) {
        var nBytes = array.length;
        var result = Buffer.alloc(nBytes);
        nShift = nShift % (nBytes * 8);
        if (nShift === 0) {
            result.set(array);
        }
        else {
            var byteOffset = (nShift / 8 | 0);
            var leftShift = nShift % 8;
            var rightShift = 8 - leftShift;
            for (var i = 0; i < nBytes; i++) {
                {
                    var leftPart = ((array[(i + byteOffset) % nBytes] << leftShift) | 0);
                    var rightPart = ((this.unsigned(array[(i + byteOffset + 1) % nBytes]) >> rightShift) | 0);
                    result[i] = ((leftPart | rightPart) | 0);
                }
            }
        }
        return result;
    }
    ;
    ROR(array, nShift) {
        return this.ROL(array, (array.length * 8) - nShift);
    }
    ;
    unsigned(b) {
        return b & 255;
    }
    ;
    SL1(array) {
        var result = Buffer.alloc(16);
        result[0] = this.SB1_$LI$()[this.unsigned(array[0])];
        result[1] = this.SB2_$LI$()[this.unsigned(array[1])];
        result[2] = this.SB3_$LI$()[this.unsigned(array[2])];
        result[3] = this.SB4_$LI$()[this.unsigned(array[3])];
        result[4] = this.SB1_$LI$()[this.unsigned(array[4])];
        result[5] = this.SB2_$LI$()[this.unsigned(array[5])];
        result[6] = this.SB3_$LI$()[this.unsigned(array[6])];
        result[7] = this.SB4_$LI$()[this.unsigned(array[7])];
        result[8] = this.SB1_$LI$()[this.unsigned(array[8])];
        result[9] = this.SB2_$LI$()[this.unsigned(array[9])];
        result[10] = this.SB3_$LI$()[this.unsigned(array[10])];
        result[11] = this.SB4_$LI$()[this.unsigned(array[11])];
        result[12] = this.SB1_$LI$()[this.unsigned(array[12])];
        result[13] = this.SB2_$LI$()[this.unsigned(array[13])];
        result[14] = this.SB3_$LI$()[this.unsigned(array[14])];
        result[15] = this.SB4_$LI$()[this.unsigned(array[15])];
        return result;
    }
    ;
    SL2(array) {
        var result = Buffer.alloc(16);
        result[0] = this.SB3_$LI$()[this.unsigned(array[0])];
        result[1] = this.SB4_$LI$()[this.unsigned(array[1])];
        result[2] = this.SB1_$LI$()[this.unsigned(array[2])];
        result[3] = this.SB2_$LI$()[this.unsigned(array[3])];
        result[4] = this.SB3_$LI$()[this.unsigned(array[4])];
        result[5] = this.SB4_$LI$()[this.unsigned(array[5])];
        result[6] = this.SB1_$LI$()[this.unsigned(array[6])];
        result[7] = this.SB2_$LI$()[this.unsigned(array[7])];
        result[8] = this.SB3_$LI$()[this.unsigned(array[8])];
        result[9] = this.SB4_$LI$()[this.unsigned(array[9])];
        result[10] = this.SB1_$LI$()[this.unsigned(array[10])];
        result[11] = this.SB2_$LI$()[this.unsigned(array[11])];
        result[12] = this.SB3_$LI$()[this.unsigned(array[12])];
        result[13] = this.SB4_$LI$()[this.unsigned(array[13])];
        result[14] = this.SB1_$LI$()[this.unsigned(array[14])];
        result[15] = this.SB2_$LI$()[this.unsigned(array[15])];
        return result;
    }
    ;
    FO(D, RK) {
        return this.A(this.SL1(this.XOR(D, RK)));
    }
    ;
    FE(D, RK) {
        return this.A(this.SL2(this.XOR(D, RK)));
    }
    ;
    A(b) {
        var length = b.length;
        if (length !== 16) {
            throw new Error("Illegal input size. Diffusion layer should take 16-byte string as parameter.");
        }
        else {
            var result = Buffer.alloc(16);
            result[0] = ((b[3] ^ b[4] ^ b[6] ^ b[8] ^ b[9] ^ b[13] ^ b[14]) | 0);
            result[1] = ((b[2] ^ b[5] ^ b[7] ^ b[8] ^ b[9] ^ b[12] ^ b[15]) | 0);
            result[2] = ((b[1] ^ b[4] ^ b[6] ^ b[10] ^ b[11] ^ b[12] ^ b[15]) | 0);
            result[3] = ((b[0] ^ b[5] ^ b[7] ^ b[10] ^ b[11] ^ b[13] ^ b[14]) | 0);
            result[4] = ((b[0] ^ b[2] ^ b[5] ^ b[8] ^ b[11] ^ b[14] ^ b[15]) | 0);
            result[5] = ((b[1] ^ b[3] ^ b[4] ^ b[9] ^ b[10] ^ b[14] ^ b[15]) | 0);
            result[6] = ((b[0] ^ b[2] ^ b[7] ^ b[9] ^ b[10] ^ b[12] ^ b[13]) | 0);
            result[7] = ((b[1] ^ b[3] ^ b[6] ^ b[8] ^ b[11] ^ b[12] ^ b[13]) | 0);
            result[8] = ((b[0] ^ b[1] ^ b[4] ^ b[7] ^ b[10] ^ b[13] ^ b[15]) | 0);
            result[9] = ((b[0] ^ b[1] ^ b[5] ^ b[6] ^ b[11] ^ b[12] ^ b[14]) | 0);
            result[10] = ((b[2] ^ b[3] ^ b[5] ^ b[6] ^ b[8] ^ b[13] ^ b[15]) | 0);
            result[11] = ((b[2] ^ b[3] ^ b[4] ^ b[7] ^ b[9] ^ b[12] ^ b[14]) | 0);
            result[12] = ((b[1] ^ b[2] ^ b[6] ^ b[7] ^ b[9] ^ b[11] ^ b[12]) | 0);
            result[13] = ((b[0] ^ b[3] ^ b[6] ^ b[7] ^ b[8] ^ b[10] ^ b[13]) | 0);
            result[14] = ((b[0] ^ b[3] ^ b[4] ^ b[5] ^ b[9] ^ b[11] ^ b[14]) | 0);
            result[15] = ((b[1] ^ b[2] ^ b[4] ^ b[5] ^ b[8] ^ b[10] ^ b[15]) | 0);
            return result;
        }
    }
    ;
    scheduleKey(key) {
        this.mKeyLength = 16;
        var CK1;
        var CK2;
        var CK3;
        if (this.mKeyLength === 16) {
            CK1 = this.C1_$LI$();
            CK2 = this.C2_$LI$();
            CK3 = this.C3_$LI$();
            this.mNumberRounds = 12;
        }
        else if (this.mKeyLength === 24) {
            CK1 = this.C2_$LI$();
            CK2 = this.C3_$LI$();
            CK3 = this.C1_$LI$();
            this.mNumberRounds = 14;
        }
        else if (this.mKeyLength === 32) {
            CK1 = this.C3_$LI$();
            CK2 = this.C1_$LI$();
            CK3 = this.C2_$LI$();
            this.mNumberRounds = 16;
        }
        else {
            throw new Error("Illegal key length. Only 128, 192 and 256 bit keys are valid.");
        }
        var W0 = key.subarray(0, 16);
        var KR = (this.mKeyLength > 16) ? extendBuffer(key.subarray(16, key.length), 16, 0) : Buffer.alloc(16);
        var W1 = this.XOR(this.FO(W0, CK1), KR);
        var W2 = this.XOR(this.FE(W1, CK2), W0);
        var W3 = this.XOR(this.FO(W2, CK3), W1);
        this.mEK = new Array(17);
        this.mEK[0] = this.XOR(W0, this.ROR(W1, 19));
        this.mEK[1] = this.XOR(W1, this.ROR(W2, 19));
        this.mEK[2] = this.XOR(W2, this.ROR(W3, 19));
        this.mEK[3] = this.XOR(this.ROR(W0, 19), W3);
        this.mEK[4] = this.XOR(W0, this.ROR(W1, 31));
        this.mEK[5] = this.XOR(W1, this.ROR(W2, 31));
        this.mEK[6] = this.XOR(W2, this.ROR(W3, 31));
        this.mEK[7] = this.XOR(this.ROR(W0, 31), W3);
        this.mEK[8] = this.XOR(W0, this.ROL(W1, 61));
        this.mEK[9] = this.XOR(W1, this.ROL(W2, 61));
        this.mEK[10] = this.XOR(W2, this.ROL(W3, 61));
        this.mEK[11] = this.XOR(this.ROL(W0, 61), W3);
        this.mEK[12] = this.XOR(W0, this.ROL(W1, 31));
        this.mEK[13] = this.XOR(W1, this.ROL(W2, 31));
        this.mEK[14] = this.XOR(W2, this.ROL(W3, 31));
        this.mEK[15] = this.XOR(this.ROL(W0, 31), W3);
        this.mEK[16] = this.XOR(W0, this.ROL(W1, 19));
        this.mDK = new Array(this.mNumberRounds + 1);
        this.mDK[0] = this.mEK[this.mNumberRounds];
        for (var i = 1; i < this.mNumberRounds; i++) {
            this.mDK[i] = this.A(this.mEK[this.mNumberRounds - i]);
        }
        this.mDK[this.mNumberRounds] = this.mEK[0];
    }
    ;
    encrypt_block(start_chunk, last_block) {
        let text = start_chunk;
        if (last_block) {
            text = this.padd_block(start_chunk);
        }
        if (this.iv_set == true) {
            text = xor(text, this.iv);
        }
        var keys = this.mEK;
        var length = text.length;
        var result = Buffer.alloc(length);
        var block = Buffer.alloc(this.mKeyLength);
        var nBlocks = (length / this.mKeyLength | 0);
        for (var i = 0; i < nBlocks; i++) {
            {
                var currentPos = i * this.mKeyLength;
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.subarray(srcOff, srcOff + size);
                        for (var i_1 = 0; i_1 < size; i_1++)
                            dstPts[dstOff++] = tmp[i_1];
                    }
                })(text, currentPos, block, 0, this.mKeyLength);
                block = this.FO(block, keys[0]);
                for (var j = 1; j < this.mNumberRounds - 1; j++) {
                    block = (j % 2) === 0 ? this.FO(block, keys[j]) : this.FE(block, keys[j]);
                }
                block = this.XOR(this.SL2(this.XOR(block, keys[this.mNumberRounds - 1])), keys[this.mNumberRounds]);
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.subarray(srcOff, srcOff + size);
                        for (var i_2 = 0; i_2 < size; i_2++)
                            dstPts[dstOff++] = tmp[i_2];
                    }
                })(block, 0, result, currentPos, this.mKeyLength);
            }
        }
        if (this.iv_set == true) {
            this.iv = result;
        }
        return result;
    }
    ;
    decrypt_block(start_chunk, last_block) {
        var text = start_chunk;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = text;
        var keys = this.mDK;
        var length = text.length;
        var result = Buffer.alloc(length);
        var block = Buffer.alloc(this.mKeyLength);
        var nBlocks = (length / this.mKeyLength | 0);
        for (var i = 0; i < nBlocks; i++) {
            {
                var currentPos = i * this.mKeyLength;
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.subarray(srcOff, srcOff + size);
                        for (var i_1 = 0; i_1 < size; i_1++)
                            dstPts[dstOff++] = tmp[i_1];
                    }
                })(text, currentPos, block, 0, this.mKeyLength);
                block = this.FO(block, keys[0]);
                for (var j = 1; j < this.mNumberRounds - 1; j++) {
                    block = (j % 2) === 0 ? this.FO(block, keys[j]) : this.FE(block, keys[j]);
                }
                block = this.XOR(this.SL2(this.XOR(block, keys[this.mNumberRounds - 1])), keys[this.mNumberRounds]);
                /* arraycopy */ (function (srcPts, srcOff, dstPts, dstOff, size) {
                    if (srcPts !== dstPts || dstOff >= srcOff + size) {
                        while (--size >= 0)
                            dstPts[dstOff++] = srcPts[srcOff++];
                    }
                    else {
                        var tmp = srcPts.subarray(srcOff, srcOff + size);
                        for (var i_2 = 0; i_2 < size; i_2++)
                            dstPts[dstOff++] = tmp[i_2];
                    }
                })(block, 0, result, currentPos, this.mKeyLength);
            }
        }
        var return_buffer = result;
        if (this.iv_set == true) {
            return_buffer = this.XOR(result, this.iv);
        }
        if (last_block) {
            var padd_value = align(return_buffer.length, 16);
            return removePKCSPadding(return_buffer, padd_value, true);
        }
        return return_buffer;
    }
    ;
    padd_block(data) {
        const block_size = 16;
        if (data.length % block_size != 0) {
            var padd_value = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(padd_value, padd_value & 0xFF);
            data = Buffer.concat([data, paddbuffer]);
        }
        return data;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer```
     */
    encrypt(data_in, padding = 0) {
        const block_size = this.mKeyLength;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer} data_in - ```Buffer``
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns ```Buffer```
     */
    decrypt(data_in, remove_padding = true) {
        const block_size = this.mKeyLength;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            var return_block = this.decrypt_block(block);
            if ((remove_padding != false) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
class CAMELLIA {
    key;
    key_set = false;
    iv;
    iv_set = false;
    previous_block;
    MASK8 = 0xFF;
    initialized = false;
    _keyis128 = false;
    subkey = new Uint32Array(96);
    kw = new Uint32Array(8);
    ke = new Uint32Array(12);
    state = new Uint32Array(4);
    constructor() {
    }
    SIGMA = new Uint32Array([
        0xa09e667f, 0x3bcc908b,
        0xb67ae858, 0x4caa73b2,
        0xc6ef372f, 0xe94f82be,
        0x54ff53a5, 0xf1d36f1c,
        0x10e527fa, 0xde682d1d,
        0xb05688c2, 0xb3e6c1fd
    ]);
    SBOX1_1110 = new Uint32Array([
        0x70707000, 0x82828200, 0x2c2c2c00, 0xececec00, 0xb3b3b300, 0x27272700,
        0xc0c0c000, 0xe5e5e500, 0xe4e4e400, 0x85858500, 0x57575700, 0x35353500,
        0xeaeaea00, 0x0c0c0c00, 0xaeaeae00, 0x41414100, 0x23232300, 0xefefef00,
        0x6b6b6b00, 0x93939300, 0x45454500, 0x19191900, 0xa5a5a500, 0x21212100,
        0xededed00, 0x0e0e0e00, 0x4f4f4f00, 0x4e4e4e00, 0x1d1d1d00, 0x65656500,
        0x92929200, 0xbdbdbd00, 0x86868600, 0xb8b8b800, 0xafafaf00, 0x8f8f8f00,
        0x7c7c7c00, 0xebebeb00, 0x1f1f1f00, 0xcecece00, 0x3e3e3e00, 0x30303000,
        0xdcdcdc00, 0x5f5f5f00, 0x5e5e5e00, 0xc5c5c500, 0x0b0b0b00, 0x1a1a1a00,
        0xa6a6a600, 0xe1e1e100, 0x39393900, 0xcacaca00, 0xd5d5d500, 0x47474700,
        0x5d5d5d00, 0x3d3d3d00, 0xd9d9d900, 0x01010100, 0x5a5a5a00, 0xd6d6d600,
        0x51515100, 0x56565600, 0x6c6c6c00, 0x4d4d4d00, 0x8b8b8b00, 0x0d0d0d00,
        0x9a9a9a00, 0x66666600, 0xfbfbfb00, 0xcccccc00, 0xb0b0b000, 0x2d2d2d00,
        0x74747400, 0x12121200, 0x2b2b2b00, 0x20202000, 0xf0f0f000, 0xb1b1b100,
        0x84848400, 0x99999900, 0xdfdfdf00, 0x4c4c4c00, 0xcbcbcb00, 0xc2c2c200,
        0x34343400, 0x7e7e7e00, 0x76767600, 0x05050500, 0x6d6d6d00, 0xb7b7b700,
        0xa9a9a900, 0x31313100, 0xd1d1d100, 0x17171700, 0x04040400, 0xd7d7d700,
        0x14141400, 0x58585800, 0x3a3a3a00, 0x61616100, 0xdedede00, 0x1b1b1b00,
        0x11111100, 0x1c1c1c00, 0x32323200, 0x0f0f0f00, 0x9c9c9c00, 0x16161600,
        0x53535300, 0x18181800, 0xf2f2f200, 0x22222200, 0xfefefe00, 0x44444400,
        0xcfcfcf00, 0xb2b2b200, 0xc3c3c300, 0xb5b5b500, 0x7a7a7a00, 0x91919100,
        0x24242400, 0x08080800, 0xe8e8e800, 0xa8a8a800, 0x60606000, 0xfcfcfc00,
        0x69696900, 0x50505000, 0xaaaaaa00, 0xd0d0d000, 0xa0a0a000, 0x7d7d7d00,
        0xa1a1a100, 0x89898900, 0x62626200, 0x97979700, 0x54545400, 0x5b5b5b00,
        0x1e1e1e00, 0x95959500, 0xe0e0e000, 0xffffff00, 0x64646400, 0xd2d2d200,
        0x10101000, 0xc4c4c400, 0x00000000, 0x48484800, 0xa3a3a300, 0xf7f7f700,
        0x75757500, 0xdbdbdb00, 0x8a8a8a00, 0x03030300, 0xe6e6e600, 0xdadada00,
        0x09090900, 0x3f3f3f00, 0xdddddd00, 0x94949400, 0x87878700, 0x5c5c5c00,
        0x83838300, 0x02020200, 0xcdcdcd00, 0x4a4a4a00, 0x90909000, 0x33333300,
        0x73737300, 0x67676700, 0xf6f6f600, 0xf3f3f300, 0x9d9d9d00, 0x7f7f7f00,
        0xbfbfbf00, 0xe2e2e200, 0x52525200, 0x9b9b9b00, 0xd8d8d800, 0x26262600,
        0xc8c8c800, 0x37373700, 0xc6c6c600, 0x3b3b3b00, 0x81818100, 0x96969600,
        0x6f6f6f00, 0x4b4b4b00, 0x13131300, 0xbebebe00, 0x63636300, 0x2e2e2e00,
        0xe9e9e900, 0x79797900, 0xa7a7a700, 0x8c8c8c00, 0x9f9f9f00, 0x6e6e6e00,
        0xbcbcbc00, 0x8e8e8e00, 0x29292900, 0xf5f5f500, 0xf9f9f900, 0xb6b6b600,
        0x2f2f2f00, 0xfdfdfd00, 0xb4b4b400, 0x59595900, 0x78787800, 0x98989800,
        0x06060600, 0x6a6a6a00, 0xe7e7e700, 0x46464600, 0x71717100, 0xbababa00,
        0xd4d4d400, 0x25252500, 0xababab00, 0x42424200, 0x88888800, 0xa2a2a200,
        0x8d8d8d00, 0xfafafa00, 0x72727200, 0x07070700, 0xb9b9b900, 0x55555500,
        0xf8f8f800, 0xeeeeee00, 0xacacac00, 0x0a0a0a00, 0x36363600, 0x49494900,
        0x2a2a2a00, 0x68686800, 0x3c3c3c00, 0x38383800, 0xf1f1f100, 0xa4a4a400,
        0x40404000, 0x28282800, 0xd3d3d300, 0x7b7b7b00, 0xbbbbbb00, 0xc9c9c900,
        0x43434300, 0xc1c1c100, 0x15151500, 0xe3e3e300, 0xadadad00, 0xf4f4f400,
        0x77777700, 0xc7c7c700, 0x80808000, 0x9e9e9e00
    ]);
    SBOX4_4404 = new Uint32Array([
        0x70700070, 0x2c2c002c, 0xb3b300b3, 0xc0c000c0, 0xe4e400e4, 0x57570057,
        0xeaea00ea, 0xaeae00ae, 0x23230023, 0x6b6b006b, 0x45450045, 0xa5a500a5,
        0xeded00ed, 0x4f4f004f, 0x1d1d001d, 0x92920092, 0x86860086, 0xafaf00af,
        0x7c7c007c, 0x1f1f001f, 0x3e3e003e, 0xdcdc00dc, 0x5e5e005e, 0x0b0b000b,
        0xa6a600a6, 0x39390039, 0xd5d500d5, 0x5d5d005d, 0xd9d900d9, 0x5a5a005a,
        0x51510051, 0x6c6c006c, 0x8b8b008b, 0x9a9a009a, 0xfbfb00fb, 0xb0b000b0,
        0x74740074, 0x2b2b002b, 0xf0f000f0, 0x84840084, 0xdfdf00df, 0xcbcb00cb,
        0x34340034, 0x76760076, 0x6d6d006d, 0xa9a900a9, 0xd1d100d1, 0x04040004,
        0x14140014, 0x3a3a003a, 0xdede00de, 0x11110011, 0x32320032, 0x9c9c009c,
        0x53530053, 0xf2f200f2, 0xfefe00fe, 0xcfcf00cf, 0xc3c300c3, 0x7a7a007a,
        0x24240024, 0xe8e800e8, 0x60600060, 0x69690069, 0xaaaa00aa, 0xa0a000a0,
        0xa1a100a1, 0x62620062, 0x54540054, 0x1e1e001e, 0xe0e000e0, 0x64640064,
        0x10100010, 0x00000000, 0xa3a300a3, 0x75750075, 0x8a8a008a, 0xe6e600e6,
        0x09090009, 0xdddd00dd, 0x87870087, 0x83830083, 0xcdcd00cd, 0x90900090,
        0x73730073, 0xf6f600f6, 0x9d9d009d, 0xbfbf00bf, 0x52520052, 0xd8d800d8,
        0xc8c800c8, 0xc6c600c6, 0x81810081, 0x6f6f006f, 0x13130013, 0x63630063,
        0xe9e900e9, 0xa7a700a7, 0x9f9f009f, 0xbcbc00bc, 0x29290029, 0xf9f900f9,
        0x2f2f002f, 0xb4b400b4, 0x78780078, 0x06060006, 0xe7e700e7, 0x71710071,
        0xd4d400d4, 0xabab00ab, 0x88880088, 0x8d8d008d, 0x72720072, 0xb9b900b9,
        0xf8f800f8, 0xacac00ac, 0x36360036, 0x2a2a002a, 0x3c3c003c, 0xf1f100f1,
        0x40400040, 0xd3d300d3, 0xbbbb00bb, 0x43430043, 0x15150015, 0xadad00ad,
        0x77770077, 0x80800080, 0x82820082, 0xecec00ec, 0x27270027, 0xe5e500e5,
        0x85850085, 0x35350035, 0x0c0c000c, 0x41410041, 0xefef00ef, 0x93930093,
        0x19190019, 0x21210021, 0x0e0e000e, 0x4e4e004e, 0x65650065, 0xbdbd00bd,
        0xb8b800b8, 0x8f8f008f, 0xebeb00eb, 0xcece00ce, 0x30300030, 0x5f5f005f,
        0xc5c500c5, 0x1a1a001a, 0xe1e100e1, 0xcaca00ca, 0x47470047, 0x3d3d003d,
        0x01010001, 0xd6d600d6, 0x56560056, 0x4d4d004d, 0x0d0d000d, 0x66660066,
        0xcccc00cc, 0x2d2d002d, 0x12120012, 0x20200020, 0xb1b100b1, 0x99990099,
        0x4c4c004c, 0xc2c200c2, 0x7e7e007e, 0x05050005, 0xb7b700b7, 0x31310031,
        0x17170017, 0xd7d700d7, 0x58580058, 0x61610061, 0x1b1b001b, 0x1c1c001c,
        0x0f0f000f, 0x16160016, 0x18180018, 0x22220022, 0x44440044, 0xb2b200b2,
        0xb5b500b5, 0x91910091, 0x08080008, 0xa8a800a8, 0xfcfc00fc, 0x50500050,
        0xd0d000d0, 0x7d7d007d, 0x89890089, 0x97970097, 0x5b5b005b, 0x95950095,
        0xffff00ff, 0xd2d200d2, 0xc4c400c4, 0x48480048, 0xf7f700f7, 0xdbdb00db,
        0x03030003, 0xdada00da, 0x3f3f003f, 0x94940094, 0x5c5c005c, 0x02020002,
        0x4a4a004a, 0x33330033, 0x67670067, 0xf3f300f3, 0x7f7f007f, 0xe2e200e2,
        0x9b9b009b, 0x26260026, 0x37370037, 0x3b3b003b, 0x96960096, 0x4b4b004b,
        0xbebe00be, 0x2e2e002e, 0x79790079, 0x8c8c008c, 0x6e6e006e, 0x8e8e008e,
        0xf5f500f5, 0xb6b600b6, 0xfdfd00fd, 0x59590059, 0x98980098, 0x6a6a006a,
        0x46460046, 0xbaba00ba, 0x25250025, 0x42420042, 0xa2a200a2, 0xfafa00fa,
        0x07070007, 0x55550055, 0xeeee00ee, 0x0a0a000a, 0x49490049, 0x68680068,
        0x38380038, 0xa4a400a4, 0x28280028, 0x7b7b007b, 0xc9c900c9, 0xc1c100c1,
        0xe3e300e3, 0xf4f400f4, 0xc7c700c7, 0x9e9e009e
    ]);
    SBOX2_0222 = new Uint32Array([
        0x00e0e0e0, 0x00050505, 0x00585858, 0x00d9d9d9, 0x00676767, 0x004e4e4e,
        0x00818181, 0x00cbcbcb, 0x00c9c9c9, 0x000b0b0b, 0x00aeaeae, 0x006a6a6a,
        0x00d5d5d5, 0x00181818, 0x005d5d5d, 0x00828282, 0x00464646, 0x00dfdfdf,
        0x00d6d6d6, 0x00272727, 0x008a8a8a, 0x00323232, 0x004b4b4b, 0x00424242,
        0x00dbdbdb, 0x001c1c1c, 0x009e9e9e, 0x009c9c9c, 0x003a3a3a, 0x00cacaca,
        0x00252525, 0x007b7b7b, 0x000d0d0d, 0x00717171, 0x005f5f5f, 0x001f1f1f,
        0x00f8f8f8, 0x00d7d7d7, 0x003e3e3e, 0x009d9d9d, 0x007c7c7c, 0x00606060,
        0x00b9b9b9, 0x00bebebe, 0x00bcbcbc, 0x008b8b8b, 0x00161616, 0x00343434,
        0x004d4d4d, 0x00c3c3c3, 0x00727272, 0x00959595, 0x00ababab, 0x008e8e8e,
        0x00bababa, 0x007a7a7a, 0x00b3b3b3, 0x00020202, 0x00b4b4b4, 0x00adadad,
        0x00a2a2a2, 0x00acacac, 0x00d8d8d8, 0x009a9a9a, 0x00171717, 0x001a1a1a,
        0x00353535, 0x00cccccc, 0x00f7f7f7, 0x00999999, 0x00616161, 0x005a5a5a,
        0x00e8e8e8, 0x00242424, 0x00565656, 0x00404040, 0x00e1e1e1, 0x00636363,
        0x00090909, 0x00333333, 0x00bfbfbf, 0x00989898, 0x00979797, 0x00858585,
        0x00686868, 0x00fcfcfc, 0x00ececec, 0x000a0a0a, 0x00dadada, 0x006f6f6f,
        0x00535353, 0x00626262, 0x00a3a3a3, 0x002e2e2e, 0x00080808, 0x00afafaf,
        0x00282828, 0x00b0b0b0, 0x00747474, 0x00c2c2c2, 0x00bdbdbd, 0x00363636,
        0x00222222, 0x00383838, 0x00646464, 0x001e1e1e, 0x00393939, 0x002c2c2c,
        0x00a6a6a6, 0x00303030, 0x00e5e5e5, 0x00444444, 0x00fdfdfd, 0x00888888,
        0x009f9f9f, 0x00656565, 0x00878787, 0x006b6b6b, 0x00f4f4f4, 0x00232323,
        0x00484848, 0x00101010, 0x00d1d1d1, 0x00515151, 0x00c0c0c0, 0x00f9f9f9,
        0x00d2d2d2, 0x00a0a0a0, 0x00555555, 0x00a1a1a1, 0x00414141, 0x00fafafa,
        0x00434343, 0x00131313, 0x00c4c4c4, 0x002f2f2f, 0x00a8a8a8, 0x00b6b6b6,
        0x003c3c3c, 0x002b2b2b, 0x00c1c1c1, 0x00ffffff, 0x00c8c8c8, 0x00a5a5a5,
        0x00202020, 0x00898989, 0x00000000, 0x00909090, 0x00474747, 0x00efefef,
        0x00eaeaea, 0x00b7b7b7, 0x00151515, 0x00060606, 0x00cdcdcd, 0x00b5b5b5,
        0x00121212, 0x007e7e7e, 0x00bbbbbb, 0x00292929, 0x000f0f0f, 0x00b8b8b8,
        0x00070707, 0x00040404, 0x009b9b9b, 0x00949494, 0x00212121, 0x00666666,
        0x00e6e6e6, 0x00cecece, 0x00ededed, 0x00e7e7e7, 0x003b3b3b, 0x00fefefe,
        0x007f7f7f, 0x00c5c5c5, 0x00a4a4a4, 0x00373737, 0x00b1b1b1, 0x004c4c4c,
        0x00919191, 0x006e6e6e, 0x008d8d8d, 0x00767676, 0x00030303, 0x002d2d2d,
        0x00dedede, 0x00969696, 0x00262626, 0x007d7d7d, 0x00c6c6c6, 0x005c5c5c,
        0x00d3d3d3, 0x00f2f2f2, 0x004f4f4f, 0x00191919, 0x003f3f3f, 0x00dcdcdc,
        0x00797979, 0x001d1d1d, 0x00525252, 0x00ebebeb, 0x00f3f3f3, 0x006d6d6d,
        0x005e5e5e, 0x00fbfbfb, 0x00696969, 0x00b2b2b2, 0x00f0f0f0, 0x00313131,
        0x000c0c0c, 0x00d4d4d4, 0x00cfcfcf, 0x008c8c8c, 0x00e2e2e2, 0x00757575,
        0x00a9a9a9, 0x004a4a4a, 0x00575757, 0x00848484, 0x00111111, 0x00454545,
        0x001b1b1b, 0x00f5f5f5, 0x00e4e4e4, 0x000e0e0e, 0x00737373, 0x00aaaaaa,
        0x00f1f1f1, 0x00dddddd, 0x00595959, 0x00141414, 0x006c6c6c, 0x00929292,
        0x00545454, 0x00d0d0d0, 0x00787878, 0x00707070, 0x00e3e3e3, 0x00494949,
        0x00808080, 0x00505050, 0x00a7a7a7, 0x00f6f6f6, 0x00777777, 0x00939393,
        0x00868686, 0x00838383, 0x002a2a2a, 0x00c7c7c7, 0x005b5b5b, 0x00e9e9e9,
        0x00eeeeee, 0x008f8f8f, 0x00010101, 0x003d3d3d
    ]);
    SBOX3_3033 = new Uint32Array([
        0x38003838, 0x41004141, 0x16001616, 0x76007676, 0xd900d9d9, 0x93009393,
        0x60006060, 0xf200f2f2, 0x72007272, 0xc200c2c2, 0xab00abab, 0x9a009a9a,
        0x75007575, 0x06000606, 0x57005757, 0xa000a0a0, 0x91009191, 0xf700f7f7,
        0xb500b5b5, 0xc900c9c9, 0xa200a2a2, 0x8c008c8c, 0xd200d2d2, 0x90009090,
        0xf600f6f6, 0x07000707, 0xa700a7a7, 0x27002727, 0x8e008e8e, 0xb200b2b2,
        0x49004949, 0xde00dede, 0x43004343, 0x5c005c5c, 0xd700d7d7, 0xc700c7c7,
        0x3e003e3e, 0xf500f5f5, 0x8f008f8f, 0x67006767, 0x1f001f1f, 0x18001818,
        0x6e006e6e, 0xaf00afaf, 0x2f002f2f, 0xe200e2e2, 0x85008585, 0x0d000d0d,
        0x53005353, 0xf000f0f0, 0x9c009c9c, 0x65006565, 0xea00eaea, 0xa300a3a3,
        0xae00aeae, 0x9e009e9e, 0xec00ecec, 0x80008080, 0x2d002d2d, 0x6b006b6b,
        0xa800a8a8, 0x2b002b2b, 0x36003636, 0xa600a6a6, 0xc500c5c5, 0x86008686,
        0x4d004d4d, 0x33003333, 0xfd00fdfd, 0x66006666, 0x58005858, 0x96009696,
        0x3a003a3a, 0x09000909, 0x95009595, 0x10001010, 0x78007878, 0xd800d8d8,
        0x42004242, 0xcc00cccc, 0xef00efef, 0x26002626, 0xe500e5e5, 0x61006161,
        0x1a001a1a, 0x3f003f3f, 0x3b003b3b, 0x82008282, 0xb600b6b6, 0xdb00dbdb,
        0xd400d4d4, 0x98009898, 0xe800e8e8, 0x8b008b8b, 0x02000202, 0xeb00ebeb,
        0x0a000a0a, 0x2c002c2c, 0x1d001d1d, 0xb000b0b0, 0x6f006f6f, 0x8d008d8d,
        0x88008888, 0x0e000e0e, 0x19001919, 0x87008787, 0x4e004e4e, 0x0b000b0b,
        0xa900a9a9, 0x0c000c0c, 0x79007979, 0x11001111, 0x7f007f7f, 0x22002222,
        0xe700e7e7, 0x59005959, 0xe100e1e1, 0xda00dada, 0x3d003d3d, 0xc800c8c8,
        0x12001212, 0x04000404, 0x74007474, 0x54005454, 0x30003030, 0x7e007e7e,
        0xb400b4b4, 0x28002828, 0x55005555, 0x68006868, 0x50005050, 0xbe00bebe,
        0xd000d0d0, 0xc400c4c4, 0x31003131, 0xcb00cbcb, 0x2a002a2a, 0xad00adad,
        0x0f000f0f, 0xca00caca, 0x70007070, 0xff00ffff, 0x32003232, 0x69006969,
        0x08000808, 0x62006262, 0x00000000, 0x24002424, 0xd100d1d1, 0xfb00fbfb,
        0xba00baba, 0xed00eded, 0x45004545, 0x81008181, 0x73007373, 0x6d006d6d,
        0x84008484, 0x9f009f9f, 0xee00eeee, 0x4a004a4a, 0xc300c3c3, 0x2e002e2e,
        0xc100c1c1, 0x01000101, 0xe600e6e6, 0x25002525, 0x48004848, 0x99009999,
        0xb900b9b9, 0xb300b3b3, 0x7b007b7b, 0xf900f9f9, 0xce00cece, 0xbf00bfbf,
        0xdf00dfdf, 0x71007171, 0x29002929, 0xcd00cdcd, 0x6c006c6c, 0x13001313,
        0x64006464, 0x9b009b9b, 0x63006363, 0x9d009d9d, 0xc000c0c0, 0x4b004b4b,
        0xb700b7b7, 0xa500a5a5, 0x89008989, 0x5f005f5f, 0xb100b1b1, 0x17001717,
        0xf400f4f4, 0xbc00bcbc, 0xd300d3d3, 0x46004646, 0xcf00cfcf, 0x37003737,
        0x5e005e5e, 0x47004747, 0x94009494, 0xfa00fafa, 0xfc00fcfc, 0x5b005b5b,
        0x97009797, 0xfe00fefe, 0x5a005a5a, 0xac00acac, 0x3c003c3c, 0x4c004c4c,
        0x03000303, 0x35003535, 0xf300f3f3, 0x23002323, 0xb800b8b8, 0x5d005d5d,
        0x6a006a6a, 0x92009292, 0xd500d5d5, 0x21002121, 0x44004444, 0x51005151,
        0xc600c6c6, 0x7d007d7d, 0x39003939, 0x83008383, 0xdc00dcdc, 0xaa00aaaa,
        0x7c007c7c, 0x77007777, 0x56005656, 0x05000505, 0x1b001b1b, 0xa400a4a4,
        0x15001515, 0x34003434, 0x1e001e1e, 0x1c001c1c, 0xf800f8f8, 0x52005252,
        0x20002020, 0x14001414, 0xe900e9e9, 0xbd00bdbd, 0xdd00dddd, 0xe400e4e4,
        0xa100a1a1, 0xe000e0e0, 0x8a008a8a, 0xf100f1f1, 0xd600d6d6, 0x7a007a7a,
        0xbb00bbbb, 0xe300e3e3, 0x40004040, 0x4f004f4f
    ]);
    rightRotate(x, s) {
        return (((x) >>> (s)) + ((x) << (32 - s)));
    }
    leftRotate(x, s) {
        return (((x) << (s)) + ((x) >>> (32 - s)));
    }
    roldq(rot, ki, ioff, ko, ooff) {
        ko[0 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[2 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }
    decroldq(rot, ki, ioff, ko, ooff) {
        ko[2 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[0 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }
    roldqo32(rot, ki, ioff, ko, ooff) {
        ko[0 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[2 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }
    decroldqo32(rot, ki, ioff, ko, ooff) {
        ko[2 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[0 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }
    bytes2int(src, offset) {
        var word = new Uint32Array(1);
        for (var i = 0; i < 4; i++) {
            {
                word[0] = (word[0] << 8) + (src[i + offset] & this.MASK8);
            }
        }
        return word[0];
    }
    int2bytes(word, dst, offset) {
        for (var i = 0; i < 4; i++) {
            {
                dst[(3 - i) + offset] = (word | 0);
                word >>>= 8;
            }
        }
    }
    camelliaF2(s, skey, keyoff) {
        var t1;
        var t2;
        var u;
        var v;
        t1 = s[0] ^ skey[0 + keyoff];
        u = this.SBOX4_4404[t1 & this.MASK8];
        u ^= this.SBOX3_3033[(t1 >>> 8) & this.MASK8];
        u ^= this.SBOX2_0222[(t1 >>> 16) & this.MASK8];
        u ^= this.SBOX1_1110[(t1 >>> 24) & this.MASK8];
        t2 = s[1] ^ skey[1 + keyoff];
        v = this.SBOX1_1110[t2 & this.MASK8];
        v ^= this.SBOX4_4404[(t2 >>> 8) & this.MASK8];
        v ^= this.SBOX3_3033[(t2 >>> 16) & this.MASK8];
        v ^= this.SBOX2_0222[(t2 >>> 24) & this.MASK8];
        s[2] ^= u ^ v;
        s[3] ^= u ^ v ^ this.rightRotate(u, 8);
        t1 = s[2] ^ skey[2 + keyoff];
        u = this.SBOX4_4404[t1 & this.MASK8];
        u ^= this.SBOX3_3033[(t1 >>> 8) & this.MASK8];
        u ^= this.SBOX2_0222[(t1 >>> 16) & this.MASK8];
        u ^= this.SBOX1_1110[(t1 >>> 24) & this.MASK8];
        t2 = s[3] ^ skey[3 + keyoff];
        v = this.SBOX1_1110[t2 & this.MASK8];
        v ^= this.SBOX4_4404[(t2 >>> 8) & this.MASK8];
        v ^= this.SBOX3_3033[(t2 >>> 16) & this.MASK8];
        v ^= this.SBOX2_0222[(t2 >>> 24) & this.MASK8];
        s[0] ^= u ^ v;
        s[1] ^= u ^ v ^ this.rightRotate(u, 8);
    }
    camelliaFLs(s, fkey, keyoff) {
        s[1] ^= this.leftRotate(s[0] & fkey[0 + keyoff], 1);
        s[0] ^= fkey[1 + keyoff] | s[1];
        s[2] ^= fkey[3 + keyoff] | s[3];
        s[3] ^= this.leftRotate(fkey[2 + keyoff] & s[2], 1);
    }
    setkey(forEncryption, key) {
        var k = new Uint32Array(8);
        var ka = new Uint32Array(4);
        var kb = new Uint32Array(4);
        var t = new Uint32Array(4);
        switch ((key.length)) {
            case 16:
                this._keyis128 = true;
                k[0] = this.bytes2int(key, 0);
                k[1] = this.bytes2int(key, 4);
                k[2] = this.bytes2int(key, 8);
                k[3] = this.bytes2int(key, 12);
                k[4] = k[5] = k[6] = k[7] = 0;
                break;
            case 24:
                k[0] = this.bytes2int(key, 0);
                k[1] = this.bytes2int(key, 4);
                k[2] = this.bytes2int(key, 8);
                k[3] = this.bytes2int(key, 12);
                k[4] = this.bytes2int(key, 16);
                k[5] = this.bytes2int(key, 20);
                k[6] = ~k[4];
                k[7] = ~k[5];
                this._keyis128 = false;
                break;
            case 32:
                k[0] = this.bytes2int(key, 0);
                k[1] = this.bytes2int(key, 4);
                k[2] = this.bytes2int(key, 8);
                k[3] = this.bytes2int(key, 12);
                k[4] = this.bytes2int(key, 16);
                k[5] = this.bytes2int(key, 20);
                k[6] = this.bytes2int(key, 24);
                k[7] = this.bytes2int(key, 28);
                this._keyis128 = false;
                break;
            default:
                throw Error("key sizes are only 16/24/32 bytes.");
        }
        for (var i = 0; i < 4; i++) {
            {
                ka[i] = k[i] ^ k[i + 4];
            }
        }
        this.camelliaF2(ka, this.SIGMA, 0);
        for (var i = 0; i < 4; i++) {
            {
                ka[i] ^= k[i];
            }
        }
        this.camelliaF2(ka, this.SIGMA, 4);
        if (this._keyis128) {
            if (forEncryption) {
                this.kw[0] = k[0];
                this.kw[1] = k[1];
                this.kw[2] = k[2];
                this.kw[3] = k[3];
                this.roldq(15, k, 0, this.subkey, 4);
                this.roldq(30, k, 0, this.subkey, 12);
                this.roldq(15, k, 0, t, 0);
                this.subkey[18] = t[2];
                this.subkey[19] = t[3];
                this.roldq(17, k, 0, this.ke, 4);
                this.roldq(17, k, 0, this.subkey, 24);
                this.roldq(17, k, 0, this.subkey, 32);
                this.subkey[0] = ka[0];
                this.subkey[1] = ka[1];
                this.subkey[2] = ka[2];
                this.subkey[3] = ka[3];
                this.roldq(15, ka, 0, this.subkey, 8);
                this.roldq(15, ka, 0, this.ke, 0);
                this.roldq(15, ka, 0, t, 0);
                this.subkey[16] = t[0];
                this.subkey[17] = t[1];
                this.roldq(15, ka, 0, this.subkey, 20);
                this.roldqo32(34, ka, 0, this.subkey, 28);
                this.roldq(17, ka, 0, this.kw, 4);
            }
            else {
                this.kw[4] = k[0];
                this.kw[5] = k[1];
                this.kw[6] = k[2];
                this.kw[7] = k[3];
                this.decroldq(15, k, 0, this.subkey, 28);
                this.decroldq(30, k, 0, this.subkey, 20);
                this.decroldq(15, k, 0, t, 0);
                this.subkey[16] = t[0];
                this.subkey[17] = t[1];
                this.decroldq(17, k, 0, this.ke, 0);
                this.decroldq(17, k, 0, this.subkey, 8);
                this.decroldq(17, k, 0, this.subkey, 0);
                this.subkey[34] = ka[0];
                this.subkey[35] = ka[1];
                this.subkey[32] = ka[2];
                this.subkey[33] = ka[3];
                this.decroldq(15, ka, 0, this.subkey, 24);
                this.decroldq(15, ka, 0, this.ke, 4);
                this.decroldq(15, ka, 0, t, 0);
                this.subkey[18] = t[2];
                this.subkey[19] = t[3];
                this.decroldq(15, ka, 0, this.subkey, 12);
                this.decroldqo32(34, ka, 0, this.subkey, 4);
                this.roldq(17, ka, 0, this.kw, 0);
            }
        }
        else {
            for (var i = 0; i < 4; i++) {
                {
                    kb[i] = ka[i] ^ k[i + 4];
                }
            }
            this.camelliaF2(kb, this.SIGMA, 8);
            if (forEncryption) {
                this.kw[0] = k[0];
                this.kw[1] = k[1];
                this.kw[2] = k[2];
                this.kw[3] = k[3];
                this.roldqo32(45, k, 0, this.subkey, 16);
                this.roldq(15, k, 0, this.ke, 4);
                this.roldq(17, k, 0, this.subkey, 32);
                this.roldqo32(34, k, 0, this.subkey, 44);
                this.roldq(15, k, 4, this.subkey, 4);
                this.roldq(15, k, 4, this.ke, 0);
                this.roldq(30, k, 4, this.subkey, 24);
                this.roldqo32(34, k, 4, this.subkey, 36);
                this.roldq(15, ka, 0, this.subkey, 8);
                this.roldq(30, ka, 0, this.subkey, 20);
                this.ke[8] = ka[1];
                this.ke[9] = ka[2];
                this.ke[10] = ka[3];
                this.ke[11] = ka[0];
                this.roldqo32(49, ka, 0, this.subkey, 40);
                this.subkey[0] = kb[0];
                this.subkey[1] = kb[1];
                this.subkey[2] = kb[2];
                this.subkey[3] = kb[3];
                this.roldq(30, kb, 0, this.subkey, 12);
                this.roldq(30, kb, 0, this.subkey, 28);
                this.roldqo32(51, kb, 0, this.kw, 4);
            }
            else {
                this.kw[4] = k[0];
                this.kw[5] = k[1];
                this.kw[6] = k[2];
                this.kw[7] = k[3];
                this.decroldqo32(45, k, 0, this.subkey, 28);
                this.decroldq(15, k, 0, this.ke, 4);
                this.decroldq(17, k, 0, this.subkey, 12);
                this.decroldqo32(34, k, 0, this.subkey, 0);
                this.decroldq(15, k, 4, this.subkey, 40);
                this.decroldq(15, k, 4, this.ke, 8);
                this.decroldq(30, k, 4, this.subkey, 20);
                this.decroldqo32(34, k, 4, this.subkey, 8);
                this.decroldq(15, ka, 0, this.subkey, 36);
                this.decroldq(30, ka, 0, this.subkey, 24);
                this.ke[2] = ka[1];
                this.ke[3] = ka[2];
                this.ke[0] = ka[3];
                this.ke[1] = ka[0];
                this.decroldqo32(49, ka, 0, this.subkey, 4);
                this.subkey[46] = kb[0];
                this.subkey[47] = kb[1];
                this.subkey[44] = kb[2];
                this.subkey[45] = kb[3];
                this.decroldq(30, kb, 0, this.subkey, 32);
                this.decroldq(30, kb, 0, this.subkey, 16);
                this.roldqo32(51, kb, 0, this.kw, 0);
            }
        }
        this.initialized = true;
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer} iv - ```Buffer```
     */
    set_iv(iv) {
        if (iv.length != 16) {
            throw Error("IV must be 16 bytes long");
        }
        this.iv = iv;
        this.iv_set = true;
    }
    ;
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer} key - ```Buffer```
     */
    set_key(key) {
        switch ((key.length)) {
            case 16:
                this._keyis128 = true;
                break;
            case 24:
                this._keyis128 = false;
                break;
            case 32:
                this._keyis128 = false;
                break;
            default:
                throw Error("key sizes are only 16/24/32 bytes.");
        }
        this.key = key;
        this.key_set = true;
    }
    ;
    encrypt_block(block, last_block) {
        if (!this.initialized) {
            this.setkey(true, this.key);
        }
        if (last_block) {
            block = this.padd_block(block);
        }
        if (this.iv_set == true) {
            block = xor(block, this.iv);
        }
        const return_block = this.processBlock(block);
        if (this.iv_set == true) {
            this.iv = return_block;
        }
        return return_block;
    }
    ;
    decrypt_block(block, last_block) {
        if (!this.initialized) {
            this.setkey(false, this.key);
        }
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = block;
        var return_block = this.processBlock(block);
        if (this.iv_set == true) {
            return_block = xor(return_block, this.iv);
        }
        if (last_block) {
            var padd_value = align(return_block.length, 16);
            return removePKCSPadding(return_block, padd_value, true);
        }
        return return_block;
    }
    ;
    padd_block(data) {
        const block_size = 16;
        if (data.length % block_size != 0) {
            var padd_value = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(padd_value, padd_value & 0xFF);
            data = Buffer.concat([data, paddbuffer]);
        }
        return data;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer```
     */
    encrypt(data_in, padding = 0) {
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        this.setkey(true, this.key);
        const block_size = 16;
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0; index < data.length / block_size; index++) {
            var block = data.subarray((index * block_size), (index + 1) * block_size);
            if (this.iv_set == true) {
                block = xor(block, this.iv);
            }
            const return_block = this.processBlock(block);
            if (this.iv_set == true) {
                this.iv = return_block;
            }
            return_buff.push(return_block);
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns ```Buffer```
     */
    decrypt(data_in, remove_padding = true) {
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        this.setkey(false, this.key);
        const block_size = 16;
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            var block = data.subarray((index * block_size), (index + 1) * block_size);
            if (this.iv_set == true) {
                if (this.previous_block != undefined) {
                    this.iv = this.previous_block;
                }
            }
            this.previous_block = block;
            var return_block = this.processBlock(block);
            if (this.iv_set == true) {
                return_block = xor(return_block, this.iv);
            }
            if ((remove_padding != false) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    processBlock(__in) {
        if (!this.initialized) {
            throw Error("Camellia is not initialized");
        }
        if (this._keyis128) {
            return this.processBlock128(__in);
        }
        else {
            return this.processBlock192or256(__in);
        }
    }
    ;
    processBlock128(__in) {
        for (var i = 0; i < 4; i++) {
            {
                this.state[i] = this.bytes2int(__in, (i * 4));
                this.state[i] ^= this.kw[i];
            }
        }
        this.camelliaF2(this.state, this.subkey, 0);
        this.camelliaF2(this.state, this.subkey, 4);
        this.camelliaF2(this.state, this.subkey, 8);
        this.camelliaFLs(this.state, this.ke, 0);
        this.camelliaF2(this.state, this.subkey, 12);
        this.camelliaF2(this.state, this.subkey, 16);
        this.camelliaF2(this.state, this.subkey, 20);
        this.camelliaFLs(this.state, this.ke, 4);
        this.camelliaF2(this.state, this.subkey, 24);
        this.camelliaF2(this.state, this.subkey, 28);
        this.camelliaF2(this.state, this.subkey, 32);
        this.state[2] ^= this.kw[4];
        this.state[3] ^= this.kw[5];
        this.state[0] ^= this.kw[6];
        this.state[1] ^= this.kw[7];
        var out = Buffer.alloc(16);
        this.int2bytes(this.state[2], out, 0);
        this.int2bytes(this.state[3], out, 4);
        this.int2bytes(this.state[0], out, 8);
        this.int2bytes(this.state[1], out, 12);
        return out;
    }
    ;
    processBlock192or256(__in) {
        for (var i = 0; i < 4; i++) {
            {
                this.state[i] = this.bytes2int(__in, (i * 4));
                this.state[i] ^= this.kw[i];
            }
        }
        this.camelliaF2(this.state, this.subkey, 0);
        this.camelliaF2(this.state, this.subkey, 4);
        this.camelliaF2(this.state, this.subkey, 8);
        this.camelliaFLs(this.state, this.ke, 0);
        this.camelliaF2(this.state, this.subkey, 12);
        this.camelliaF2(this.state, this.subkey, 16);
        this.camelliaF2(this.state, this.subkey, 20);
        this.camelliaFLs(this.state, this.ke, 4);
        this.camelliaF2(this.state, this.subkey, 24);
        this.camelliaF2(this.state, this.subkey, 28);
        this.camelliaF2(this.state, this.subkey, 32);
        this.camelliaFLs(this.state, this.ke, 8);
        this.camelliaF2(this.state, this.subkey, 36);
        this.camelliaF2(this.state, this.subkey, 40);
        this.camelliaF2(this.state, this.subkey, 44);
        this.state[2] ^= this.kw[4];
        this.state[3] ^= this.kw[5];
        this.state[0] ^= this.kw[6];
        this.state[1] ^= this.kw[7];
        var out = Buffer.alloc(16);
        this.int2bytes(this.state[2], out, 0);
        this.int2bytes(this.state[3], out, 4);
        this.int2bytes(this.state[0], out, 8);
        this.int2bytes(this.state[1], out, 12);
        return out;
    }
    ;
}

class JPExtData {
    type;
    data;
    constructor(type, data) {
        this.type = type;
        this.data = data;
    }
}
class JPExtensionCodec {
    static defaultCodec = new JPExtensionCodec();
    // ensures ExtensionCodecType<X> matches ExtensionCodec<X>
    // this will make type errors a lot more clear
    // eslint-disable-next-line @typescript-eslint/naming-convention
    __brand;
    // custom extensions
    encoders = [];
    decoders = [];
    constructor(extension) {
        if (extension) {
            this.register(extension);
        }
    }
    ;
    register(extension) {
        // custom extensions
        if ((extension.type < 0 || extension.type > 0xCF)) {
            throw new Error(`Type EXT number is outside of allowed range (0x0 - 0xCF but got 0x${extension.type.toString(16).padStart(2, "0")})`);
        }
        this.encoders[extension.type] = extension.encode;
        this.decoders[extension.type] = extension.decode;
    }
    ;
    tryToEncode(object, encoder, context) {
        // custom extensions
        for (let i = 0; i < this.encoders.length; i++) {
            const encodeExt = this.encoders[i];
            if (encodeExt != null) {
                const data = encodeExt(object, encoder, context);
                if (data != null) {
                    const type = i;
                    return new JPExtData(type, data);
                }
            }
        }
        if (object instanceof JPExtData) {
            // to keep ExtData as is
            return object;
        }
        return null;
    }
    ;
    decode(data, decoder, type, context) {
        const decodeExt = this.decoders[type];
        if (decodeExt) {
            return decodeExt(data, decoder, type, context);
        }
        else {
            // decode() does not fail, returns ExtData instead.
            return new JPExtData(type, data.data);
        }
    }
}

var version = "1.0.2";
var pack = {
	version: version};

/**
 * Get build version string.
 *
 * @returns {{VERSION_MAJOR: ubyte, VERSION_MINOR: ubyte}}
 */
function GetVer() {
    const ver = /(\d+)(\.)(\d+)(\.)(\d+)/g.exec(pack.version);
    return {
        VERSION_MAJOR: parseInt(ver ? ver[1] : "0"),
        VERSION_MINOR: parseInt(ver ? ver[3] : "0"),
    };
}
const { 
/**
 * Build verion number to check the file creation params
 */
VERSION_MAJOR, 
/**
 * Build verion number to check the file creation params
 */
VERSION_MINOR } = GetVer();
/**
 * Build verion number to check the file creation params
 */
const VERSION_NUMBER = parseFloat(`${VERSION_MAJOR}.${VERSION_MINOR}`);
/**
 * Max Buffer size.
 *
 * @returns {number}
 */
function MAX_LENGTH() {
    return constants.MAX_LENGTH;
}
/**
 * Max Buffer size for this system.
 */
const MAX_BUFFER = MAX_LENGTH() || 0x100000000;
function isFloat32Safe(value) {
    if (!Number.isFinite(value))
        return true; // Infinity, -Infinity, NaN all store fine
    const f32 = new Float32Array(1);
    f32[0] = value;
    return f32[0] === value;
}
/**
 * 512kb zip chunks
 */
const CHUNK_SIZE = 512 * 1024;
/**
 * Compress a file using Deflate, framed with [length][chunk] blocks.
 */
function deflateFileSync(inWriter, outWriter) {
    inWriter.open();
    outWriter.open();
    let bytesToProcess = inWriter.size;
    let bytesStart = 0;
    let bytesRead = 0;
    do {
        bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
        if (bytesRead > 0) {
            const chunk = inWriter.read(bytesStart, bytesRead, true);
            const compressed = zlib.deflateSync(chunk);
            outWriter.uint32le = compressed.length;
            outWriter.overwrite(compressed, true);
            bytesToProcess -= bytesRead;
            bytesStart += bytesRead;
        }
    } while (bytesRead === CHUNK_SIZE);
}
/**
 * Decompress a framed deflate-compressed file.
 */
function inflateFileSync(inReader, outWriter) {
    inReader.open();
    outWriter.open();
    let bytesToProcess = inReader.size;
    let bytesStart = 0;
    let bytesRead = 0;
    do {
        bytesRead = inReader.uint32;
        bytesStart += 4;
        if (bytesRead > 0) {
            const chunk = inReader.read(bytesStart, bytesRead, true);
            bytesToProcess -= chunk.length;
            const uncompressed = zlib.inflateSync(chunk);
            outWriter.overwrite(uncompressed, true);
            bytesStart += bytesRead;
        }
    } while (bytesStart < bytesToProcess);
}
/**
 * Compress a Buffer using Deflate, framed with [length][chunk] blocks.
 */
function deflateBuffer(inWriter) {
    let bytesToProcess = inWriter.size;
    let bytesStart = 0;
    let bytesRead = 0;
    const buffers = [];
    do {
        bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
        if (bytesRead > 0) {
            const chunk = inWriter.read(bytesStart, bytesRead, true);
            const compressed = zlib.deflateSync(chunk);
            const lenBuf = Buffer.alloc(4);
            lenBuf.writeUInt32LE(compressed.length, 0);
            buffers.push(lenBuf);
            buffers.push(compressed);
            bytesToProcess -= bytesRead;
            bytesStart += bytesRead;
        }
    } while (bytesRead === CHUNK_SIZE);
    return Buffer.concat(buffers);
}
/**
 * Decompress a framed deflate-compressed buffer.
 */
function inflateBuffer(bw) {
    const startingOff = bw.offset;
    const size = bw.size;
    const totalBuffer = size - startingOff;
    let bytesRead = 0;
    const buffers = [];
    while (bytesRead < totalBuffer) {
        const chunkLen = bw.readUInt32LE();
        bytesRead += 4;
        const compressed = bw.extract(chunkLen);
        bytesRead += chunkLen;
        const decompressed = zlib.inflateSync(compressed);
        buffers.push(decompressed);
    }
    return Buffer.concat(buffers);
}
function isArrayBufferLike(buffer) {
    return (buffer instanceof ArrayBuffer || (typeof SharedArrayBuffer !== "undefined" && buffer instanceof SharedArrayBuffer));
}
function ensureBuffer(buffer) {
    if (buffer instanceof Buffer) {
        return buffer;
    }
    else if (buffer instanceof Uint8Array) {
        return Buffer.from(buffer);
    }
    else if (ArrayBuffer.isView(buffer)) {
        return Buffer.from(buffer.buffer);
    }
    else if (isArrayBufferLike(buffer)) {
        return Buffer.from(buffer);
    }
    else {
        // ArrayLike<number>
        return Buffer.from(buffer);
    }
}
/**
 * Internal index for values.
 */
var JPType;
(function (JPType) {
    // 0x00 - 0x7F positive fixint 
    JPType[JPType["OBJECT_0"] = 128] = "OBJECT_0";
    JPType[JPType["OBJECT_1"] = 129] = "OBJECT_1";
    JPType[JPType["OBJECT_2"] = 130] = "OBJECT_2";
    JPType[JPType["OBJECT_3"] = 131] = "OBJECT_3";
    JPType[JPType["OBJECT_4"] = 132] = "OBJECT_4";
    JPType[JPType["OBJECT_5"] = 133] = "OBJECT_5";
    JPType[JPType["OBJECT_6"] = 134] = "OBJECT_6";
    JPType[JPType["OBJECT_7"] = 135] = "OBJECT_7";
    JPType[JPType["OBJECT_8"] = 136] = "OBJECT_8";
    JPType[JPType["OBJECT_9"] = 137] = "OBJECT_9";
    JPType[JPType["OBJECT_10"] = 138] = "OBJECT_10";
    JPType[JPType["OBJECT_11"] = 139] = "OBJECT_11";
    JPType[JPType["OBJECT_12"] = 140] = "OBJECT_12";
    JPType[JPType["OBJECT_13"] = 141] = "OBJECT_13";
    JPType[JPType["OBJECT_14"] = 142] = "OBJECT_14";
    JPType[JPType["OBJECT_15"] = 143] = "OBJECT_15";
    JPType[JPType["ARRAY_0"] = 144] = "ARRAY_0";
    JPType[JPType["ARRAY_1"] = 145] = "ARRAY_1";
    JPType[JPType["ARRAY_2"] = 146] = "ARRAY_2";
    JPType[JPType["ARRAY_3"] = 147] = "ARRAY_3";
    JPType[JPType["ARRAY_4"] = 148] = "ARRAY_4";
    JPType[JPType["ARRAY_5"] = 149] = "ARRAY_5";
    JPType[JPType["ARRAY_6"] = 150] = "ARRAY_6";
    JPType[JPType["ARRAY_7"] = 151] = "ARRAY_7";
    JPType[JPType["ARRAY_8"] = 152] = "ARRAY_8";
    JPType[JPType["ARRAY_9"] = 153] = "ARRAY_9";
    JPType[JPType["ARRAY_10"] = 154] = "ARRAY_10";
    JPType[JPType["ARRAY_11"] = 155] = "ARRAY_11";
    JPType[JPType["ARRAY_12"] = 156] = "ARRAY_12";
    JPType[JPType["ARRAY_13"] = 157] = "ARRAY_13";
    JPType[JPType["ARRAY_14"] = 158] = "ARRAY_14";
    JPType[JPType["ARRAY_15"] = 159] = "ARRAY_15";
    JPType[JPType["KEY_0"] = 160] = "KEY_0";
    JPType[JPType["KEY_1"] = 161] = "KEY_1";
    JPType[JPType["KEY_2"] = 162] = "KEY_2";
    JPType[JPType["KEY_3"] = 163] = "KEY_3";
    JPType[JPType["KEY_4"] = 164] = "KEY_4";
    JPType[JPType["KEY_5"] = 165] = "KEY_5";
    JPType[JPType["KEY_6"] = 166] = "KEY_6";
    JPType[JPType["KEY_7"] = 167] = "KEY_7";
    JPType[JPType["KEY_8"] = 168] = "KEY_8";
    JPType[JPType["KEY_9"] = 169] = "KEY_9";
    JPType[JPType["KEY_10"] = 170] = "KEY_10";
    JPType[JPType["KEY_11"] = 171] = "KEY_11";
    JPType[JPType["KEY_12"] = 172] = "KEY_12";
    JPType[JPType["KEY_13"] = 173] = "KEY_13";
    JPType[JPType["KEY_14"] = 174] = "KEY_14";
    JPType[JPType["KEY_15"] = 175] = "KEY_15";
    JPType[JPType["STR_0"] = 176] = "STR_0";
    JPType[JPType["STR_1"] = 177] = "STR_1";
    JPType[JPType["STR_2"] = 178] = "STR_2";
    JPType[JPType["STR_3"] = 179] = "STR_3";
    JPType[JPType["STR_4"] = 180] = "STR_4";
    JPType[JPType["STR_5"] = 181] = "STR_5";
    JPType[JPType["STR_6"] = 182] = "STR_6";
    JPType[JPType["STR_7"] = 183] = "STR_7";
    JPType[JPType["STR_8"] = 184] = "STR_8";
    JPType[JPType["STR_9"] = 185] = "STR_9";
    JPType[JPType["STR_10"] = 186] = "STR_10";
    JPType[JPType["STR_11"] = 187] = "STR_11";
    JPType[JPType["STR_12"] = 188] = "STR_12";
    JPType[JPType["STR_13"] = 189] = "STR_13";
    JPType[JPType["STR_14"] = 190] = "STR_14";
    JPType[JPType["STR_15"] = 191] = "STR_15";
    JPType[JPType["NULL"] = 192] = "NULL";
    JPType[JPType["UNDEFINED"] = 193] = "UNDEFINED";
    JPType[JPType["BOOL_FALSE"] = 194] = "BOOL_FALSE";
    JPType[JPType["BOOL_TRUE"] = 195] = "BOOL_TRUE";
    JPType[JPType["FINISHED"] = 196] = "FINISHED";
    JPType[JPType["LIST_END"] = 197] = "LIST_END";
    JPType[JPType["UNUSED_C6"] = 198] = "UNUSED_C6";
    JPType[JPType["OBJECT8"] = 199] = "OBJECT8";
    JPType[JPType["OBJECT16"] = 200] = "OBJECT16";
    JPType[JPType["OBJECT32"] = 201] = "OBJECT32";
    JPType[JPType["FLOAT32"] = 202] = "FLOAT32";
    JPType[JPType["FLOAT64"] = 203] = "FLOAT64";
    JPType[JPType["UINT_8"] = 204] = "UINT_8";
    JPType[JPType["UINT_16"] = 205] = "UINT_16";
    JPType[JPType["UINT_32"] = 206] = "UINT_32";
    JPType[JPType["UINT_64"] = 207] = "UINT_64";
    JPType[JPType["INT_8"] = 208] = "INT_8";
    JPType[JPType["INT_16"] = 209] = "INT_16";
    JPType[JPType["INT_32"] = 210] = "INT_32";
    JPType[JPType["INT_64"] = 211] = "INT_64";
    JPType[JPType["KEY8"] = 212] = "KEY8";
    JPType[JPType["KEY16"] = 213] = "KEY16";
    JPType[JPType["KEY32"] = 214] = "KEY32";
    JPType[JPType["STR8"] = 215] = "STR8";
    JPType[JPType["STR16"] = 216] = "STR16";
    JPType[JPType["STR32"] = 217] = "STR32";
    JPType[JPType["ARRAY8"] = 218] = "ARRAY8";
    JPType[JPType["ARRAY16"] = 219] = "ARRAY16";
    JPType[JPType["ARRAY32"] = 220] = "ARRAY32";
    JPType[JPType["EXT8"] = 221] = "EXT8";
    JPType[JPType["EXT16"] = 222] = "EXT16";
    JPType[JPType["EXT32"] = 223] = "EXT32";
    // 0xE0 - 0xFF negative fixint 
})(JPType || (JPType = {}));
/**
 * Internal index for ext values.
 */
var JPExtType;
(function (JPExtType) {
    // 0xD0 - 0xFF are reserve extend numbers
    JPExtType[JPExtType["Maps"] = 238] = "Maps";
    JPExtType[JPExtType["Sets"] = 239] = "Sets";
    JPExtType[JPExtType["Symbol"] = 240] = "Symbol";
    JPExtType[JPExtType["RegEx"] = 241] = "RegEx";
    JPExtType[JPExtType["BigUint64Array"] = 242] = "BigUint64Array";
    JPExtType[JPExtType["BigInt64Array"] = 243] = "BigInt64Array";
    JPExtType[JPExtType["Float64Array"] = 244] = "Float64Array";
    JPExtType[JPExtType["Float32Array"] = 245] = "Float32Array";
    JPExtType[JPExtType["Float16Array"] = 246] = "Float16Array";
    JPExtType[JPExtType["Int32Array"] = 247] = "Int32Array";
    JPExtType[JPExtType["Uint32Array"] = 248] = "Uint32Array";
    JPExtType[JPExtType["Uint16Array"] = 249] = "Uint16Array";
    JPExtType[JPExtType["Int16Array"] = 250] = "Int16Array";
    JPExtType[JPExtType["Int8Array"] = 251] = "Int8Array";
    JPExtType[JPExtType["Uint8Array"] = 252] = "Uint8Array";
    JPExtType[JPExtType["Uint8ClampedArray"] = 253] = "Uint8ClampedArray";
    JPExtType[JPExtType["Buffer"] = 254] = "Buffer";
    JPExtType[JPExtType["Date"] = 255] = "Date"; // MSGPACK Standard
})(JPExtType || (JPExtType = {}));
/**
 * For creating a unique string list
 */
class stringList {
    array = [];
    set = new Set();
    /**
     * For creating a unique string list
     *
     * @param {string[]?} stringArray
     */
    constructor(stringArray) {
        if (stringArray) {
            this.array = stringArray;
            this.set = new Set(stringArray);
        }
        else {
            this.array = [];
            this.set = new Set();
        }
    }
    ;
    /**
     * Add string
     *
     * @param {string} value
     * @returns {number} index
     */
    add(value) {
        if (!this.set.has(value)) {
            this.set.add(value);
            this.array.push(value);
        }
        return this.getIndex(value);
    }
    ;
    /**
     * Gets the string from the index
     *
     * @param {number} value
     * @returns {string}
     */
    get(value) {
        return this.array[value];
    }
    ;
    /**
     * Shouldn't ever use!
     *
     * @param {string} value
     */
    remove(value) {
        if (this.set.has(value)) {
            this.set.delete(value);
            // Find the index of the value in the array and remove it
            const index = this.array.indexOf(value);
            if (index !== -1) {
                this.array.splice(index, 1);
            }
        }
    }
    ;
    /**
     * Gets the index for the string
     *
     * @param {string} value
     * @returns {number} index
     */
    getIndex(value) {
        return this.array.indexOf(value);
    }
    ;
    /**
     * returns data as an array
     *
     * @returns {string[]} string array
     */
    getValues() {
        return this.array;
    }
    ;
    /**
     * Check the set has the value
     *
     * @param {string} value
     * @returns {boolean} if the value is in the dataset
     */
    has(value) {
        return this.set.has(value);
    }
    ;
}
class JPBase {
    ////////////////
    //  BUFFERS   //
    ////////////////
    /**
     * Buffer for header data.
     */
    headerBuffer = null;
    ////////////////
    //  WRITERS   //
    ////////////////
    useStream = false;
    valueWriter = null;
    strWriter = null;
    compWriter = null;
    ////////////////
    //  READERS   //
    ////////////////
    fileReader = null;
    valueReader = null;
    strReader = null;
    compReader = null;
    ////////////////
    //   SIZES    //
    ////////////////
    /**
     * Internal size.
     */
    _HEADER_SIZE = 0;
    /**
     * Size of the header buffer.
     */
    set HEADER_SIZE(value) {
        this._HEADER_SIZE = value;
    }
    ;
    /**
     * Size of the header buffer.
     */
    get HEADER_SIZE() {
        if (this._HEADER_SIZE != 0) {
            return this._HEADER_SIZE;
        }
        else if (this.headerBuffer != null) {
            this._HEADER_SIZE = this.headerBuffer.length;
            return this.headerBuffer.length;
        }
        else {
            var HEADER_SIZE = 32;
            if (this.Crc32) {
                HEADER_SIZE += 4;
            }
            if (this.Encrypted && !this.EncryptionExcluded) {
                HEADER_SIZE += 4;
            }
            this._HEADER_SIZE = HEADER_SIZE;
            return this._HEADER_SIZE;
        }
    }
    ;
    /**
     * Internal size.
     */
    _VALUE_SIZE = 0n;
    /**
     * The size of the section that has values data.
     */
    set VALUE_SIZE(value) {
        this._VALUE_SIZE = BigInt(value);
    }
    ;
    /**
      * The size of the section that has every other type of data.
      */
    get VALUE_SIZE() {
        if (this._VALUE_SIZE != 0n) {
            return this._VALUE_SIZE;
        }
        else if (this.valueWriter != null) {
            this.valueWriter.get;
            this._VALUE_SIZE = BigInt(this.valueWriter.offset);
            return this._VALUE_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * Internal size.
     */
    _STR_SIZE = 0n;
    /**
     * The size of the section that has string / key data.
     */
    set STR_SIZE(value) {
        this._STR_SIZE = BigInt(value);
    }
    ;
    /**
     * The size of the section that has string / key data.
     */
    get STR_SIZE() {
        if (this._STR_SIZE != 0n) {
            return this._STR_SIZE;
        }
        else if (this.strWriter != null) {
            this.strWriter.get;
            this._STR_SIZE = BigInt(this.strWriter.offset);
            return this._STR_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * Internal size.
     */
    _DATA_SIZE = 0n;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    set DATA_SIZE(value) {
        this._DATA_SIZE = BigInt(value);
    }
    ;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    get DATA_SIZE() {
        if (this._DATA_SIZE != 0n) {
            return this._DATA_SIZE;
        }
        else if (this._VALUE_SIZE != 0n && this._STR_SIZE != 0n) {
            this._DATA_SIZE = BigInt(this._VALUE_SIZE + this._STR_SIZE);
            return this._DATA_SIZE;
        }
        else if (this.strWriter != null && this.valueWriter != null) {
            this._DATA_SIZE = BigInt(this.valueWriter.size + this.strWriter.length);
            return this._DATA_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    ////////////////
    //   FLAGS    //
    ////////////////
    /**
    * Flags for file header.
    */
    flags = {
        LargeFile: 0,
        Compressed: 0,
        Crc32: 0,
        Encrypted: 0,
        EncryptionExcluded: 0,
        KeyStripped: 0
    };
    /**
     * For files over 4 gigs.
     *
     * @param {bit} bit flag
     */
    set LargeFile(bit) {
        this.flags.LargeFile = (bit & 1);
    }
    ;
    /**
     * For files over 4 gigs.
     *
     * @returns {bit} flag
     */
    get LargeFile() {
        return this.flags.LargeFile;
    }
    ;
    /**
     * If the data is zlib compressed.
     *
     * @returns {bit} flag
     */
    get Compressed() {
        return this.flags.Compressed;
    }
    ;
    /**
     * If the data is zlib compressed.
     *
     * @param {bit} bit flag
     */
    set Compressed(bit) {
        this.flags.Compressed = (bit & 1);
    }
    ;
    /**
     * If a CRC32 is done on the data.
     *
     * @returns {bit} flag
     */
    get Crc32() {
        return this.flags.Crc32;
    }
    ;
    /**
     * If a CRC32 is done on the data.
     *
     * @param {bit} bit flag
     */
    set Crc32(bit) {
        this.flags.Crc32 = (bit & 1);
    }
    ;
    /**
     * If the file is encrypted.
     *
     * @returns {bit} flag
     */
    get Encrypted() {
        return this.flags.Encrypted;
    }
    ;
    /**
     * If the file is encrypted.
     *
     * @param {bit} bit flag
     */
    set Encrypted(bit) {
        this.flags.Encrypted = (bit & 1);
    }
    ;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @returns {bit} flag
     */
    get EncryptionExcluded() {
        return this.flags.EncryptionExcluded;
    }
    ;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @param {bit} bit flag
     */
    set EncryptionExcluded(bit) {
        this.flags.EncryptionExcluded = (bit & 1);
    }
    ;
    /**
     * If the object keys are removed from the file.
     *
     * @returns {bit} flag
     */
    get KeyStripped() {
        return this.flags.KeyStripped;
    }
    ;
    /**
     * If the object keys are removed from the file.
     *
     * @param {bit} bit flag
     */
    set KeyStripped(bit) {
        this.flags.KeyStripped = (bit & 1);
    }
    ;
    ////////////////////
    // EXTRA HEADERS  //
    ////////////////////
    /**
     * Encryption key For decryption.
     */
    _encryptionKey = 0;
    /**
     * Encryption value. For decryption.
     */
    set encryptionKey(value) {
        this._encryptionKey = value >>> 0;
    }
    /**
     * Encryption value. For decryption.
     */
    get encryptionKey() {
        return this._encryptionKey;
    }
    /**
     * Check hash value. From value data on after decomp and decryption.
     */
    _CRC32 = 0;
    /**
     * Check hash value. From value data on after decomp and decryption.
     */
    set CRC32(value) {
        this._CRC32 = value;
    }
    /**
     * Check hash value. From value data on after decomp and decryption.
     */
    get CRC32() {
        return this._CRC32;
    }
    ////////////////////
    // SHARED OBJECTS //
    ////////////////////
    /**
     * Object keys for when `stripKeys` was enabled in encoding.
     *
     * This array MUST be passed to decoder for the file to be decoded.
     */
    keysArray = [];
    entered = false;
    fileName = "";
}

/**
 * `undefined` becomes string `"undefined"`
 *
 * `RegExp` becomes `{regexSrc: src, regexFlags: flags}`
 *
 * `symbol` becomes `{symbolGlobal: boolean, symbolKey: string}`
 *
 * `bigint` becomes `number` if safe, otherwise `string`
 *
 * `Set` becomes `Array`
 *
 * `Map` becomes `Array[]`
 *
 * @param {JSON} _this
 * @param {unknown} key
 * @returns unknown
 */
function stringifyFix(_this, key) {
    if (key === undefined) {
        return "undefined";
    }
    else if (key instanceof RegExp) {
        const src = key.source;
        const flags = key.flags;
        return { regexSrc: src, regexFlags: flags };
    }
    else if (typeof key == "symbol") {
        const keyCheck = Symbol.keyFor(key);
        const global = !!keyCheck;
        var keyed = keyCheck ?? key.description;
        keyed = keyed ?? "";
        return { symbolGlobal: global, symbolKey: keyed };
    }
    else if (key instanceof Set) {
        const array = [];
        for (const item of key) {
            array.push(item);
        }
        return array;
    }
    else if (key instanceof Map) {
        return Array.from(key.entries());
    }
    else if (typeof key === "bigint") {
        const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);
        const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
        if (key >= MIN_SAFE && key <= MAX_SAFE) {
            return Number(key);
        }
        else {
            return key.toString();
        }
    }
    else {
        return key;
    }
}
const STATE_ARRAY = "array";
const STATE_SET = "set";
const STATE_MAP_KEY = "map_key";
const STATE_MAP_VALUE = "map_value";
const STATE_OBJECT_KEY = "object_key";
const STATE_OBJECT_VALUE = "object_value";
const mapKeyConverter = (key) => {
    if (typeof key === "string" || typeof key === "number" || typeof key == "symbol") {
        return key;
    }
    throw new Error("The type of key must be string or number but " + typeof key);
};
class StackPool {
    stack = [];
    stackHeadPosition = -1;
    get length() {
        return this.stackHeadPosition + 1;
    }
    ;
    top() {
        return this.stack[this.stackHeadPosition];
    }
    ;
    pushArrayState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_ARRAY;
        state.position = 0;
        state.size = size;
        state.array = new Array(size);
    }
    ;
    pushSetState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_SET;
        state.position = 0;
        state.size = size;
        state.set = new Set();
    }
    ;
    pushMapState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_MAP_KEY;
        state.readCount = 0;
        state.size = size;
        state.map = new Map();
    }
    ;
    pushObjectState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_OBJECT_KEY;
        state.readCount = 0;
        state.size = size;
        state.object = {};
    }
    ;
    getUninitializedStateFromPool() {
        this.stackHeadPosition++;
        if (this.stackHeadPosition === this.stack.length) {
            const partialState = {
                type: undefined,
                size: 0,
                array: undefined,
                position: 0,
                readCount: 0,
                object: undefined,
                map: undefined,
                set: undefined,
                key: null,
            };
            this.stack.push(partialState);
        }
        return this.stack[this.stackHeadPosition];
    }
    ;
    release(state) {
        const topStackState = this.stack[this.stackHeadPosition];
        if (topStackState !== state) {
            throw new Error("Invalid stack state. Released state is not on top of the stack.");
        }
        if (state.type === STATE_SET) {
            const partialState = state;
            partialState.size = 0;
            partialState.set = undefined;
            partialState.position = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_ARRAY) {
            const partialState = state;
            partialState.size = 0;
            partialState.array = undefined;
            partialState.position = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_MAP_KEY || state.type === STATE_MAP_VALUE) {
            const partialState = state;
            partialState.size = 0;
            partialState.map = undefined;
            partialState.readCount = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_OBJECT_KEY || state.type === STATE_OBJECT_VALUE) {
            const partialState = state;
            partialState.size = 0;
            partialState.object = undefined;
            partialState.readCount = 0;
            partialState.type = undefined;
        }
        this.stackHeadPosition--;
    }
    ;
    reset() {
        this.stack.length = 0;
        this.stackHeadPosition = -1;
    }
    ;
}
/**
 * Create with `DecoderOptions`
 */
class JPDecode extends JPBase {
    extensionCodec;
    context;
    mapKeyConverter = mapKeyConverter;
    stack = new StackPool();
    stringsList = [];
    /**
     * Endianness. Defaults to `little`
     */
    endian = "little";
    /**
     * Converts return to valid JSON
     */
    makeJSON = false;
    /**
     * Ensures all 64 bit values return as `bigint`
     */
    enforceBigInt = false;
    /**
     * File Buffer
     */
    buffer = null;
    /**
     * Direct objects for any symbols that were encoded.
     */
    symbolList = [];
    /**
     * If a temp file was needed.
     */
    tempCreated = false;
    /**
     * If the file buffer has extensions types in use.
     */
    hasExtensions = false;
    /**
     * If the data is acceptable JSON data.
     */
    validJSON = true;
    /**
     * Set up with basic options.
     *
     * @param {DecoderOptions?} options - options for decoding
     */
    constructor(options) {
        super();
        this.extensionCodec = options?.extensionCodec ?? JPExtensionCodec.defaultCodec;
        this.context = options?.context; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined
        this.keysArray = options?.keysArray ? options.keysArray : [];
        this.encryptionKey = options?.encryptionKey ? options.encryptionKey : 0;
        this.enforceBigInt = options?.enforceBigInt ? options.enforceBigInt : false;
        this.makeJSON = options?.makeJSON ? options.makeJSON : false;
    }
    ;
    clone() {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return new JPDecode({
            extensionCodec: this.extensionCodec,
            context: this.context,
            keysArray: this.keysArray,
            EncryptionKey: this.encryptionKey,
            fileName: this.fileName,
            enforceBigInt: this.enforceBigInt,
            makeJSON: this.makeJSON,
            // TODO may need more
        });
    }
    ;
    /**
     * Basic decoding, will run options that were set in constructor.
     *
     * If passed a string, will assume it is a file path to read the file from.
     *
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     *
     * @param bufferOrSourcePath - Buffer of the JamPack data or the file path to a JamPack file.
     */
    decode(bufferOrSourcePath) {
        if (this.entered) {
            const instance = this.clone();
            return instance.decode(bufferOrSourcePath);
        }
        if (typeof bufferOrSourcePath != "string") {
            this.setBuffer(bufferOrSourcePath);
        }
        else {
            this.fileName = bufferOrSourcePath;
            this.checkFilePath(this.fileName);
        }
        try {
            this.entered = true;
            this.reinitializeState();
            if (this.valueReader == null) {
                throw new Error("No value reader set. " + this.fileName);
            }
            this.stringsList = this.createStringList();
            const object = this.doDecodeSync(this.valueReader);
            if (this.tempCreated) {
                this.valueReader.deleteFile();
                this.valueReader.close();
            }
            if (this.makeJSON && !this.validJSON) {
                return JSON.parse(JSON.stringify(object, stringifyFix));
            }
            return object;
        }
        catch (err) {
            console.error(err);
            return;
        }
        finally {
            this.entered = false;
        }
    }
    ;
    checkFilePath(filePath) {
        var biTest = new BiReaderStream(filePath);
        const testBuffer = biTest.extract(40);
        biTest.close();
        biTest = new BiReader(testBuffer);
        this.testHeader(biTest);
        biTest.close();
        if (!this.useStream) {
            this.buffer = fs.readFileSync(filePath);
        }
    }
    ;
    testHeader(br) {
        const MAGICS = br.uint16;
        if (!(MAGICS == 0x504A || MAGICS == 0x4A50)) {
            throw new Error(`File magics incorrect. Expecting 0x504A or 0x4A50, but got 0x${MAGICS.toString(16).padStart(4, "0")} ` + this.fileName);
        }
        if (MAGICS == 0x4A50) {
            this.endian = "big";
        }
        const V_MAJOR = br.uint8;
        const V_MINOR = br.uint8;
        this.HEADER_SIZE = br.uint8;
        this.LargeFile = br.bit1;
        this.Compressed = br.bit1;
        this.Crc32 = br.bit1;
        this.Encrypted = br.bit1;
        this.EncryptionExcluded = br.bit1;
        this.KeyStripped = br.bit1;
        br.bit1; // FLAG6
        br.bit1; // FLAG7
        br.uint8; // RESV_6 FLAG8-15
        br.uint8; // RESV_7 FLAG16-23
        this.VALUE_SIZE = br.uint64;
        this.STR_SIZE = br.uint64;
        this.DATA_SIZE = br.uint64;
        const V_NUMBER = parseFloat(`${V_MAJOR}.${V_MINOR}`);
        if (V_NUMBER > VERSION_NUMBER) {
            console.warn(`File was encoded in a more advanced version of this package which may cause issues. Package: ${VERSION_NUMBER} - File: ${V_NUMBER} ` + this.fileName);
        }
        if (this.LargeFile && (br.size > MAX_BUFFER || (this.STR_SIZE + this.VALUE_SIZE) > MAX_BUFFER)) {
            this.useStream = true;
        }
        if (this.EncryptionExcluded && this.encryptionKey == 0) {
            throw new Error('The encryption key is not included in the file and the key was not set in the decoder. Can not decode. ' + this.fileName);
        }
        if (this.KeyStripped && this.keysArray.length == 0) {
            throw new Error('The keysArray was removed from the file and not set in the decoder. Can not decode. ' + this.fileName);
        }
        // extra headers
        if (this.Crc32) {
            this.CRC32 = br.uint32;
        }
        if (this.Encrypted && !this.EncryptionExcluded) {
            this.encryptionKey = br.uint32;
        }
    }
    ;
    /**
     * Sets up valueReader & strReader. Will decomp and decrypt as well.
     *
     * If a temp file is made, will have to delete after.
     */
    reinitializeState() {
        if (this.useStream) {
            if (this.fileReader != null) {
                this.fileReader.close();
                this.fileReader = null;
            }
            this.compReader = new BiReaderStream(this.fileName);
            this.compReader.endian = this.endian;
            this.compReader.open();
            this.compReader.goto(this.HEADER_SIZE);
            this.tempCreated = false;
            if (this.Encrypted) {
                // make comp file without header
                const compWriter = new BiWriterStream(this.fileName + ".comp");
                compWriter.unrestrict();
                compWriter.endian = this.endian;
                compWriter.open();
                compWriter.overwrite(this.compReader.read(this.HEADER_SIZE, this.compReader.size - this.HEADER_SIZE), true);
                compWriter.trim();
                this.tempCreated = true;
                var finalSize = 0;
                if (this.Compressed) {
                    finalSize = Number(this.DATA_SIZE);
                }
                else {
                    finalSize = Number(this.VALUE_SIZE + this.STR_SIZE);
                }
                this.decrypt(compWriter, null, finalSize);
                compWriter.close();
                this.compReader = new BiReaderStream(this.fileName + ".comp");
                this.compReader.endian = this.endian;
                this.compReader.unrestrict();
                this.compReader.open();
            }
            if (this.Compressed) {
                // check if comp file was made
                if (this.tempCreated) {
                    // compReader should be just the data
                    const tempcompWriter = new BiWriterStream(this.fileName + ".comp.tmp");
                    tempcompWriter.endian = this.endian;
                    tempcompWriter.open();
                    inflateFileSync(this.compReader, tempcompWriter);
                    this.compReader.writeMode(true);
                    this.compReader.gotoStart();
                    this.compReader.overwrite(tempcompWriter.read(0, tempcompWriter.offset), true);
                    this.compReader.trim();
                    this.compReader.writeMode(false);
                    tempcompWriter.deleteFile();
                }
                else {
                    // split off header
                    const compWriter = new BiWriterStream(this.fileName + ".comp");
                    compWriter.endian = this.endian;
                    compWriter.open();
                    compWriter.overwrite(this.compReader.read(this.HEADER_SIZE, this.compReader.size - this.HEADER_SIZE), true);
                    compWriter.trim();
                    compWriter.close();
                    const compReader = new BiReaderStream(this.fileName + ".comp");
                    compReader.endian = this.endian;
                    compReader.unrestrict();
                    const tempcompWriter = new BiWriterStream(this.fileName + ".comp.tmp");
                    tempcompWriter.endian = this.endian;
                    tempcompWriter.open();
                    this.tempCreated = true;
                    inflateFileSync(compReader, tempcompWriter);
                    compReader.writeMode(true);
                    compReader.gotoStart();
                    compReader.overwrite(tempcompWriter.read(0, tempcompWriter.offset), true);
                    compReader.trim();
                    compReader.writeMode(false);
                    tempcompWriter.deleteFile();
                    this.compReader = compReader;
                }
            }
            if (this.Crc32) {
                const CHUNK_SIZE = 0x2000; // 8192 bytes
                var crc = 0;
                var start = this.HEADER_SIZE;
                if (this.tempCreated) {
                    start = 0;
                }
                this.compReader.goto(start);
                for (let position = start; position <= this.compReader.size;) {
                    const buffer = this.compReader.read(position, Math.min(CHUNK_SIZE, this.compReader.size - position));
                    if (buffer.length == 0)
                        break;
                    crc = CRC32(buffer, crc);
                    position += buffer.length;
                }
                crc = crc >>> 0;
                if (crc != this.CRC32) {
                    console.warn(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32} but got ${crc}. ` + this.fileName);
                }
            }
            var totalSize = 0n;
            if (this.tempCreated) {
                totalSize = BigInt(this.compReader.size);
                this.compReader.open();
                this.valueReader = new BiReaderStream(this.fileName + ".comp");
                this.strReader = new BiReaderStream(this.fileName + ".comp");
                this.valueReader.fd = this.compReader.fd;
                this.valueReader.endian = this.compReader.endian;
                this.valueReader.size = this.compReader.size;
                this.valueReader.sizeB = this.compReader.sizeB;
                this.valueReader.maxFileSize = this.compReader.maxFileSize;
                this.strReader.fd = this.compReader.fd;
                this.strReader.endian = this.compReader.endian;
                this.strReader.size = this.compReader.size;
                this.strReader.sizeB = this.compReader.sizeB;
                this.strReader.maxFileSize = this.compReader.maxFileSize;
                this.strReader.offset = Number(this.VALUE_SIZE);
            }
            else {
                totalSize = BigInt(this.compReader.size - this.HEADER_SIZE);
                this.compReader.open();
                this.valueReader = new BiReaderStream(this.fileName);
                this.strReader = new BiReaderStream(this.fileName);
                this.valueReader.fd = this.compReader.fd;
                this.valueReader.endian = this.compReader.endian;
                this.valueReader.size = this.compReader.size;
                this.valueReader.sizeB = this.compReader.sizeB;
                this.valueReader.maxFileSize = this.compReader.maxFileSize;
                this.valueReader.offset = this.HEADER_SIZE;
                this.strReader.fd = this.compReader.fd;
                this.strReader.endian = this.compReader.endian;
                this.strReader.size = this.compReader.size;
                this.strReader.sizeB = this.compReader.sizeB;
                this.strReader.maxFileSize = this.compReader.maxFileSize;
                this.strReader.offset = this.HEADER_SIZE + Number(this.VALUE_SIZE);
            }
            if (this.VALUE_SIZE + this.STR_SIZE != totalSize) {
                console.warn(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${totalSize}. ` + this.fileName);
            }
        }
        else {
            if (this.buffer == null) {
                throw new Error("Buffer not set. " + this.fileName);
            }
            this.fileReader = new BiReader(this.buffer);
            this.fileReader.endian = this.endian;
            this.fileReader.goto(this.HEADER_SIZE);
            var decomBuffer = this.buffer.subarray(this.HEADER_SIZE, this.buffer.length);
            this.compReader = new BiReader(decomBuffer);
            this.compReader.endian = this.endian;
            if (this.Encrypted) {
                var finalSize = Number(this.VALUE_SIZE + this.STR_SIZE);
                if (this.Compressed) {
                    finalSize = Number(this.DATA_SIZE);
                }
                decomBuffer = this.decrypt(null, decomBuffer, finalSize);
                this.compReader = new BiReader(decomBuffer);
                this.compReader.endian = this.endian;
            }
            if (this.Compressed) {
                decomBuffer = inflateBuffer(this.compReader);
                this.compReader = new BiReader(decomBuffer);
                this.compReader.endian = this.endian;
            }
            if (this.Crc32) {
                const data = this.compReader.data;
                const crc = CRC32(data, 0) >>> 0;
                if (crc != this.CRC32) {
                    console.warn(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32} but got ${crc}. ` + this.fileName);
                }
            }
            if (this.VALUE_SIZE + this.STR_SIZE != BigInt(this.compReader.size)) {
                console.warn(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${this.compReader.size}. ` + this.fileName);
            }
            this.valueReader = new BiReader(this.compReader.extract(Number(this.VALUE_SIZE), true));
            this.valueReader.endian = this.endian;
            this.strReader = new BiReader(this.compReader.extract(Number(this.STR_SIZE), true));
            this.strReader.endian = this.endian;
        }
    }
    ;
    setBuffer(buffer) {
        this.buffer = ensureBuffer(buffer);
        this.fileReader = new BiReader(this.buffer);
        this.testHeader(this.fileReader);
        this.fileReader.close();
        this.fileReader = null;
    }
    ;
    createStringList() {
        if (this.strReader == null) {
            throw new Error("string reader not set. " + this.fileName);
        }
        DECODE: while (true) {
            const headByte = this.strReader.ubyte;
            let object;
            if ((headByte >= JPType.ARRAY_0 && headByte <= JPType.ARRAY_15) || // arrays
                (headByte >= JPType.ARRAY8 && headByte <= JPType.ARRAY32)) {
                var size = 0;
                if (headByte <= JPType.ARRAY_15) {
                    size = headByte - JPType.ARRAY_0;
                }
                else if (headByte === JPType.ARRAY8) {
                    size = this.strReader.ubyte;
                }
                else if (headByte === JPType.ARRAY16) {
                    size = this.strReader.uint16;
                }
                else if (headByte === JPType.ARRAY32) {
                    size = this.strReader.uint32;
                }
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if ((headByte >= JPType.STR_0 && headByte <= JPType.STR_15) || // strings
                (headByte >= JPType.STR8 && headByte <= JPType.STR32)) {
                var size = 0;
                if (headByte <= JPType.STR_15) {
                    size = headByte - JPType.STR_0;
                }
                else if (headByte === JPType.STR8) {
                    size = this.strReader.ubyte;
                }
                else if (headByte === JPType.STR16) {
                    size = this.strReader.uint16;
                }
                else if (headByte === JPType.STR32) {
                    size = this.strReader.uint32;
                }
                object = this.strReader.string({ length: size });
            }
            else {
                throw new Error(`Invalid data in string area. 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }
            const stack = this.stack;
            while (stack.length > 0) {
                // arrays
                const state = stack.top();
                if (state.type === STATE_ARRAY) {
                    state.array[state.position] = object;
                    state.position++;
                    if (state.position === state.size) {
                        object = state.array;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else {
                    throw new Error('Should only have an array in the string data, found type ' + state.type + " in file " + this.fileName);
                }
            }
            return object;
        }
    }
    ;
    /**
     * Runs a raw decode on the passed `BiReader`'s Buffer. Return data wherever it ends based on the start value.
     *
     * @param reader - Reader
     * @returns Decoded data
     */
    async doDecodeAsync(reader) {
        try {
            return this.doDecodeSync(reader);
        }
        catch (err) {
            throw new Error(err);
        }
    }
    ;
    /**
     * Runs a raw decode on the passed `BiReader`'s Buffer. Return data wherever it ends based on the start value.
     *
     * @param reader - Reader
     * @returns Decoded data
     */
    doDecodeSync(reader) {
        if (reader == null) {
            throw new Error("Value reader not set. " + this.fileName);
        }
        let object;
        DECODE: while (true) {
            const headByte = reader.ubyte;
            if (headByte < JPType.OBJECT_0) {
                // positive fixint 0x00 - 0x7f
                object = headByte;
            }
            else if (headByte < JPType.ARRAY_0) {
                // fix object 0x80 - 0x8f
                const size = headByte - 0x80;
                if (size !== 0) {
                    this.pushObjectState(size);
                    continue DECODE;
                }
                else {
                    object = {};
                }
            }
            else if (headByte < JPType.KEY_0) {
                //fixarray
                const size = headByte - 0x90;
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if (headByte < JPType.STR_0) {
                //fixkey (only used in stripping)
                const index = headByte - 0xA0;
                if (!this.keysArray[index]) {
                    console.warn(`Did not find key value for index ` + index + " in file " + this.fileName);
                }
                object = this.keysArray[index];
            }
            else if (headByte < JPType.NULL) {
                //fixstr
                const index = headByte - 0xB0;
                if (this.stringsList[index] === undefined) {
                    console.warn(`Did not find string value for index ` + index + " in file " + this.fileName);
                    console.debug(this.stringsList);
                }
                object = this.stringsList[index];
            }
            else if (headByte == JPType.NULL) {
                object = null;
            }
            else if (headByte == JPType.UNDEFINED) {
                object = undefined;
                this.validJSON = false;
            }
            else if (headByte == JPType.BOOL_FALSE) {
                object = false;
            }
            else if (headByte == JPType.BOOL_TRUE) {
                object = true;
            }
            else if (headByte == JPType.FINISHED ||
                headByte == JPType.UNUSED_C6) {
                return object;
            }
            else if (headByte == JPType.LIST_END) {
                const state = this.stack.top();
                if (state.type != undefined) {
                    if (state.type == STATE_ARRAY) {
                        object = state.array;
                    }
                    else if (state.type == STATE_OBJECT_KEY || state.type == STATE_OBJECT_VALUE) {
                        object = state.object;
                    }
                    else if (state.type == STATE_MAP_KEY || state.type == STATE_MAP_VALUE) {
                        object = state.map;
                    }
                    this.stack.release(state);
                }
                return object;
            }
            else if (headByte <= JPType.OBJECT32) {
                // non-fix object
                var size = 0;
                if (headByte === JPType.OBJECT8) {
                    size = reader.ubyte;
                }
                else if (headByte === JPType.OBJECT16) {
                    size = reader.uint16;
                }
                else if (headByte === JPType.OBJECT32) {
                    size = reader.uint32;
                }
                if (size !== 0) {
                    this.pushObjectState(size);
                    continue DECODE;
                }
                else {
                    object = {};
                }
            }
            else if (headByte === JPType.FLOAT32) {
                object = reader.float;
            }
            else if (headByte === JPType.FLOAT64) {
                object = reader.doublefloat;
            }
            else if (headByte === JPType.UINT_8) {
                object = reader.uint8;
            }
            else if (headByte === JPType.UINT_16) {
                object = reader.uint16;
            }
            else if (headByte === JPType.UINT_32) {
                object = reader.uint32;
            }
            else if (headByte === JPType.UINT_64) {
                object = reader.uint64;
                if (this.enforceBigInt) {
                    object = BigInt(object);
                }
                if (typeof object === "bigint") {
                    this.validJSON = false;
                }
            }
            else if (headByte === JPType.INT_8) {
                object = reader.int8;
            }
            else if (headByte === JPType.INT_16) {
                object = reader.int16;
            }
            else if (headByte === JPType.INT_32) {
                object = reader.int32;
            }
            else if (headByte === JPType.INT_64) {
                object = reader.int64;
                if (this.enforceBigInt) {
                    object = BigInt(object);
                }
                if (typeof object === "bigint") {
                    this.validJSON = false;
                }
            }
            else if (headByte <= JPType.KEY32) {
                // nonfix key
                var index = 0;
                if (headByte === JPType.KEY8) {
                    index = reader.ubyte;
                }
                else if (headByte === JPType.KEY16) {
                    index = reader.uint16;
                }
                else if (headByte === JPType.KEY32) {
                    index = reader.uint32;
                }
                if (!this.keysArray[index]) {
                    console.warn(`Did not find key value for index ` + index + " in file " + this.fileName);
                }
                object = this.keysArray[index];
            }
            else if (headByte <= JPType.STR32) {
                // non-fix string
                var index = 0;
                if (headByte === JPType.STR8) {
                    index = reader.ubyte;
                }
                else if (headByte === JPType.STR16) {
                    index = reader.uint16;
                }
                else if (headByte === JPType.STR32) {
                    index = reader.uint32;
                }
                if (this.stringsList[index] === undefined) {
                    console.warn(`Did not find string value for index ` + index + " in file " + this.fileName);
                    console.debug(this.stringsList);
                }
                object = this.stringsList[index];
            }
            else if (headByte <= JPType.ARRAY32) {
                // non-fix array
                var size = 0;
                if (headByte === JPType.ARRAY8) {
                    size = reader.ubyte;
                }
                else if (headByte === JPType.ARRAY16) {
                    size = reader.uint16;
                }
                else if (headByte === JPType.ARRAY32) {
                    size = reader.uint32;
                }
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if (headByte <= JPType.EXT32) {
                this.hasExtensions = true;
                var size = 0;
                if (headByte === JPType.EXT8) {
                    size = reader.ubyte;
                }
                else if (headByte === JPType.EXT16) {
                    size = reader.uint16;
                }
                else if (headByte === JPType.EXT32) {
                    size = reader.uint32;
                }
                const type = reader.ubyte;
                if (type == JPExtType.Maps) {
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushMapState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Map();
                    }
                }
                else if (type == JPExtType.Sets) {
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushSetState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Set();
                    }
                }
                else {
                    object = this.decodeExtension(reader, size, type);
                }
            }
            else if (headByte > JPType.EXT32) {
                // negative fixint
                object = headByte - 0x100;
            }
            else {
                throw new Error(`Outside of index error 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }
            const stack = this.stack;
            while (stack.length > 0) {
                // arrays and maps
                const state = stack.top();
                if (state.type === STATE_ARRAY) {
                    state.array[state.position] = object;
                    state.position++;
                    if (state.position === state.size) {
                        object = state.array;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_SET) {
                    state.set.add(object);
                    state.position++;
                    if (state.position === state.size) {
                        object = state.set;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_OBJECT_KEY) {
                    if (object === "__proto__") {
                        throw new Error("The key __proto__ is not allowed " + this.fileName);
                    }
                    state.key = this.mapKeyConverter(object);
                    state.type = STATE_OBJECT_VALUE;
                    continue DECODE;
                }
                else if (state.type === STATE_OBJECT_VALUE) {
                    state.object[state.key] = object;
                    state.readCount++;
                    if (state.readCount === state.size) {
                        object = state.object;
                        stack.release(state);
                    }
                    else {
                        state.key = null;
                        state.type = STATE_OBJECT_KEY;
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_MAP_KEY) {
                    if (object === "__proto__") {
                        throw new Error("The key __proto__ is not allowed " + this.fileName);
                    }
                    state.key = this.mapKeyConverter(object);
                    state.type = STATE_MAP_VALUE;
                    continue DECODE;
                }
                else if (state.type === STATE_MAP_VALUE) {
                    // it must be `state.type === State.MAP_VALUE` here
                    state.map.set(state.key, object);
                    state.readCount++;
                    if (state.readCount === state.size) {
                        object = state.map;
                        stack.release(state);
                    }
                    else {
                        state.key = null;
                        state.type = STATE_MAP_KEY;
                        continue DECODE;
                    }
                }
            }
            return object;
        }
    }
    ;
    pushMapState(size) {
        this.stack.pushMapState(size);
    }
    ;
    pushObjectState(size) {
        this.stack.pushObjectState(size);
    }
    ;
    pushArrayState(size) {
        this.stack.pushArrayState(size);
    }
    ;
    pushSetState(size) {
        this.stack.pushSetState(size);
    }
    ;
    readString(headByte) {
        if (this.valueReader == null) {
            throw new Error("Value reader not set. " + this.fileName);
        }
        var value = "";
        if ((headByte >= JPType.STR_0 && headByte <= JPType.STR_15) || // strings
            (headByte >= JPType.STR8 && headByte <= JPType.STR32)) {
            var index = 0;
            if (headByte <= JPType.STR_15) {
                index = headByte - JPType.STR_0;
            }
            else if (headByte === JPType.STR8) {
                index = this.valueReader.ubyte;
            }
            else if (headByte === JPType.STR16) {
                index = this.valueReader.uint16;
            }
            else if (headByte === JPType.STR32) {
                index = this.valueReader.uint32;
            }
            if (this.stringsList[index] === undefined) {
                console.warn(`Did not find string value for index ` + index + " in file " + this.fileName);
                console.debug(this.stringsList);
            }
            else {
                value = this.stringsList[index];
            }
        }
        return value;
    }
    ;
    decodeExtension(valueReader, size, extType) {
        let retValue, data, holder;
        switch (extType) {
            case JPExtType.Symbol:
                this.validJSON = false;
                // bool and string
                const global = valueReader.ubyte == JPType.BOOL_TRUE ? true : false;
                var headByte = valueReader.ubyte;
                const key = this.readString(headByte);
                retValue = global ? Symbol.for(key) : Symbol(key);
                this.symbolList.push(retValue);
                break;
            case JPExtType.RegEx:
                this.validJSON = false;
                // two strings
                const source = this.readString(valueReader.ubyte);
                const flags = this.readString(valueReader.ubyte);
                retValue = new RegExp(source, flags);
                break;
            case JPExtType.Maps:
                this.validJSON = false;
                // handled before
                break;
            case JPExtType.Sets:
                this.validJSON = false;
                // handled before
                break;
            case JPExtType.BigUint64Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new BigUint64Array(holder.buffer);
                break;
            case JPExtType.BigInt64Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new BigInt64Array(holder.buffer);
                break;
            case JPExtType.Float64Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Float64Array(holder.buffer);
                break;
            case JPExtType.Float32Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Float32Array(holder.buffer);
                break;
            case JPExtType.Float16Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                // not in use yet
                //retValue = new Float16Array(holder.buffer);
                break;
            case JPExtType.Int32Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int32Array(holder.buffer);
                break;
            case JPExtType.Uint32Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint32Array(holder.buffer);
                break;
            case JPExtType.Uint16Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint16Array(holder.buffer);
                break;
            case JPExtType.Int16Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int16Array(holder.buffer);
                break;
            case JPExtType.Int8Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int8Array(holder.buffer);
                break;
            case JPExtType.Uint8Array:
                data = valueReader.extract(size, true);
                retValue = new Uint8Array(data);
                break;
            case JPExtType.Uint8ClampedArray:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint8ClampedArray(holder.buffer);
                break;
            case JPExtType.Buffer:
                retValue = valueReader.extract(size, true);
                retValue = Buffer.from(retValue);
                break;
            case JPExtType.Date:
                data = valueReader.extract(size, true);
                const br = new BiReader(data);
                br.endian = this.endian;
                switch (br.size) {
                    case 4: {
                        // timestamp 32 = { sec32 }
                        const sec = br.uint32;
                        const nsec = 0;
                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                        break;
                    }
                    case 8: {
                        // timestamp 64 = { nsec30, sec34 }
                        const nsec30AndSecHigh2 = br.uint32;
                        const secLow32 = br.uint32;
                        const sec = (nsec30AndSecHigh2 & 0x3) * 0x100000000 + secLow32;
                        const nsec = nsec30AndSecHigh2 >>> 2;
                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                        break;
                    }
                    case 12: {
                        // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
                        const nsec = br.uint32;
                        const sec = Number(br.int64);
                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                    }
                    default:
                        throw new Error(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${br.size} in file ` + this.fileName);
                }
                break;
        }
        if (retValue == undefined) {
            const data = valueReader.extract(size, true);
            const br = new BiReader(data);
            br.endian = this.endian;
            retValue = this.extensionCodec.decode(br, this, extType, this.context);
        }
        return retValue;
    }
    ;
    //////////////
    // FINALIZE //
    //////////////
    decrypt(br, buffer, finalSize) {
        const cypter = new Crypt(this.encryptionKey);
        if (!this.useStream) {
            if (buffer == null) {
                throw new Error("Buffer to decrypt not set. " + this.fileName);
            }
            const decrypted = cypter.decrypt(buffer);
            if (decrypted.length != finalSize) {
                console.warn(`Decrypted buffer size of ${decrypted.length} wasn't expected size of ${finalSize}  in file ` + this.fileName);
            }
            return decrypted;
        }
        else {
            const CHUNK_SIZE = 16;
            br.open();
            br.gotoStart();
            var buff = Buffer.alloc(0);
            var data;
            let bytesToProcess = br.size;
            let bytesStart = 0;
            let bytesRead = 0;
            let amount = Math.ceil(br.size / CHUNK_SIZE);
            for (let index = 0; index < amount; index++) {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                buff = br.read(bytesStart, bytesRead);
                if (index == (amount - 1)) {
                    data = cypter.decrypt_block(buff, true);
                }
                else {
                    data = cypter.decrypt_block(buff);
                }
                if (data.length != 0) {
                    br.overwrite(data, true);
                }
                bytesStart += buff.length;
                bytesToProcess -= buff.length;
            }
            data = cypter.decrypt_final();
            if (data.length != 0) {
                br.overwrite(data, true);
            }
            br.trim();
            if (br.size != finalSize) {
                console.warn(`Decrypted buffer size of ${br.size} wasn't expected size of ${finalSize} in file 1 + this.fileName`);
            }
            return Buffer.alloc(0);
        }
    }
    ;
}

/**
 * Create with `EncoderOptions`
 */
class JPEncode extends JPBase {
    extensionCodec;
    context;
    stringList = new stringList();
    keyList = new stringList();
    depth = 0;
    ////////////////
    // CONSTANTS  //
    ////////////////
    /**
     * JP or PJ
     */
    MAGIC = 0x504A;
    /**
     * Endianness. Defaults to ``little``
     */
    endian = "little";
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MAJOR() {
        return VERSION_MAJOR;
    }
    ;
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MINOR() {
        return VERSION_MINOR;
    }
    ;
    /**
     * Set up with basic options
     *
     * @param {EncoderOptions?} encodeOptions - options for encoding
     */
    constructor(encodeOptions) {
        super();
        this.extensionCodec = encodeOptions?.extensionCodec ?? JPExtensionCodec.defaultCodec;
        this.context = encodeOptions?.context; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined
        this.endian = encodeOptions?.endian ? encodeOptions.endian : "little";
        this.Encrypted = encodeOptions?.encrypt ? 1 : 0;
        this.EncryptionExcluded = encodeOptions?.stripEncryptKey ? 1 : 0;
        this.encryptionKey = encodeOptions?.encryptionKey ? encodeOptions.encryptionKey : 0;
        this.Compressed = encodeOptions?.compress ? 1 : 0;
        this.KeyStripped = encodeOptions?.stripKeys ? 1 : 0;
        this.Crc32 = encodeOptions?.CRC32 ? 1 : 0;
    }
    ;
    clone() {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return new JPEncode({
            extensionCodec: this.extensionCodec,
            context: this.context,
            endian: this.endian,
            Encrypted: this.Encrypted,
            EncryptionExcluded: this.EncryptionExcluded,
            EncryptionKey: this.encryptionKey,
            Compressed: this.Compressed,
            KeyStripped: this.KeyStripped,
            Crc32: this.Crc32,
            fileName: this.fileName,
            useStream: this.useStream,
            valueWriter: this.valueWriter,
            strWriter: this.strWriter,
            keysArray: this.keysArray,
            compWriter: this.compWriter
            //TODO may need more here
        });
    }
    ;
    /**
     * Basic encode, will run options that were set in constructor.
     *
     * @param {any} object - Data to encode
     * @param {string} filePath - Optional file path to write the file to directly
     * @returns {Buffer}
     */
    encode(object, filePath) {
        if (this.entered) {
            const instance = this.clone();
            return instance.encode(object, filePath);
        }
        this.fileName = filePath ? filePath : "";
        if (this.fileName != "") {
            this.useStream = true;
        }
        try {
            this.entered = true;
            this.reinitializeState();
            if (this.valueWriter == null || this.strWriter == null) {
                throw new Error("Didn't create writers. " + this.fileName);
            }
            this.doEncode(this.valueWriter, object, 1);
            this.valueWriter.ubyte = JPType.FINISHED;
            this.valueWriter.trim();
            this.VALUE_SIZE = this.valueWriter.size;
            this.writeStringsData();
            this.strWriter.ubyte = JPType.FINISHED;
            this.strWriter.trim();
            this.STR_SIZE = this.strWriter.size;
            if (this.KeyStripped) {
                this.keysArray = this.keyList.getValues();
            }
            this.finalizeBuffers();
            this.headerBuffer = this.buildHeader();
            if (this.compWriter == null) {
                throw new Error("Didn't create writer. " + this.fileName);
            }
            if (!this.useStream) {
                const compBuffer = this.compWriter.data;
                return Buffer.concat([this.headerBuffer, compBuffer]);
            }
            else {
                const fileFile = new BiWriterStream(this.fileName);
                fileFile.overwrite(this.headerBuffer, true);
                fileFile.overwrite(this.compWriter.read(0, this.compWriter.size), true);
                this.compWriter.deleteFile();
                // dummy buffer
                return Buffer.alloc(0);
            }
        }
        catch (err) {
            console.error(err);
            return Buffer.alloc(0);
        }
        finally {
            this.entered = false;
        }
    }
    ;
    reinitializeState() {
        if (this.useStream) {
            this.valueWriter = new BiWriterStream(this.fileName + ".values", { extendBufferSize: 2048 });
            this.valueWriter.endian = this.endian;
            this.strWriter = new BiWriterStream(this.fileName + ".strings", { extendBufferSize: 2048 });
            this.strWriter.endian = this.endian;
        }
        else {
            this.valueWriter = new BiWriter(Buffer.alloc(2048), { extendBufferSize: 2048 });
            this.valueWriter.endian = this.endian;
            this.strWriter = new BiWriter(Buffer.alloc(2048), { extendBufferSize: 2048 });
            this.strWriter.endian = this.endian;
        }
    }
    ;
    doEncode(valueWriter, object, depth) {
        this.depth = depth;
        if (object === null) {
            return this.encodeNull(valueWriter);
        }
        else if (object === undefined) {
            return this.encodeUndefined(valueWriter);
        }
        else if (typeof object === "boolean") {
            return this.encodeBoolean(valueWriter, object);
        }
        else if (typeof object === "number") {
            return this.encodeNumber(valueWriter, object);
        }
        else if (typeof object === "string") {
            return this.encodeString(valueWriter, object, false);
        }
        else if (typeof object === "bigint") {
            return this.encodeBigInt64(valueWriter, object);
        }
        else if (typeof object === "symbol") {
            return this.encodeSymbol(valueWriter, object); // EXT
        }
        else {
            // if (typeof object === "object")
            const ext = this.extensionCodec.tryToEncode(object, this, this.context);
            if (ext != null) {
                return this.encodeExtension(valueWriter, ext); //EXT
            }
            else if (Array.isArray(object)) {
                return this.encodeArray(valueWriter, object, this.depth);
            }
            else if (object instanceof Map) {
                return this.encodeMap(valueWriter, object, this.depth); // EXT
            }
            else if (object instanceof Set) {
                return this.encodeSet(valueWriter, object, this.depth); // EXT
            }
            else if (object instanceof RegExp) {
                return this.encodeRegEx(valueWriter, object); // EXT
            }
            else if (ArrayBuffer.isView(object) || object instanceof Buffer) {
                return this.encodeBinary(valueWriter, object); // EXT
            }
            else if (object instanceof Date) {
                return this.encodeDate(valueWriter, object); // EXT
            }
            else if (typeof object === "object") {
                return this.encodeObject(valueWriter, object, this.depth);
            }
            else {
                // function and other special object come here unless extensionCodec handles them.
                throw new Error(`Unrecognized object: ${Object.prototype.toString.apply(object)} ` + this.fileName);
            }
        }
    }
    ;
    //////////////
    // STANDARD //
    //////////////
    /**
     * Writes an `Object` to the buffer as `Record<string, unknown>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeObject(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        var length = 1;
        const keys = Object.keys(object);
        const size = keys.length;
        if (size < 16) {
            // fixmap
            valueWriter.ubyte = JPType.OBJECT_0 + size;
        }
        else if (size < 0x100) {
            // map 8
            valueWriter.ubyte = JPType.OBJECT8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            // map 16
            valueWriter.ubyte = JPType.OBJECT16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            // map 32
            valueWriter.ubyte = JPType.OBJECT32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            throw new Error(`Too large map object: ${size} in file ` + this.fileName);
        }
        for (const key of keys) {
            const value = object[key];
            length += this.encodeString(valueWriter, key, true);
            length += this.doEncode(valueWriter, value, depth + 1);
        }
        return length;
    }
    ;
    /**
     * Writes an `Array` to the buffer as `Array<unknown>`
     *
     * @param valueWriter - Writer
     * @param array - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeArray(valueWriter, array, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        var length = 1;
        const size = array.length;
        if (size < 16) {
            // fixarray
            valueWriter.ubyte = JPType.ARRAY_0 + size;
        }
        else if (size < 0x100) {
            // uint8
            valueWriter.ubyte = JPType.ARRAY8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            // array 16
            valueWriter.ubyte = JPType.ARRAY16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            // array 32
            valueWriter.ubyte = JPType.ARRAY32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            throw new Error(`Too large array: ${size} in file ` + this.fileName);
        }
        for (const item of array) {
            length += this.doEncode(valueWriter, item, depth + 1);
        }
        return length;
    }
    ;
    /**
     * Writes a `string` to the buffer's string section.
     *
     * @param valueWriter - Writer
     * @param string - Data to encode
     * @param isKey If the string is used a an Object key. Only used when `stripKeys` is enabled.
     * @returns The `number` of bytes written
     */
    encodeString(valueWriter, string, isKey) {
        if (isKey == undefined) {
            isKey = false;
        }
        var length = 1;
        if (isKey && this.KeyStripped) {
            const index = this.keyList.add(string);
            if (index < 16) {
                valueWriter.ubyte = JPType.KEY_0 + index;
            }
            else if (index < 0x100) {
                // uint8
                valueWriter.ubyte = JPType.KEY8;
                valueWriter.ubyte = index;
                length++;
            }
            else if (index < 0x10000) {
                // unit16
                valueWriter.ubyte = JPType.KEY16;
                valueWriter.ushort = index;
                length += 2;
            }
            else if (index < 0x100000000) {
                // unit32
                valueWriter.ubyte = JPType.KEY32;
                valueWriter.ushort = index;
                length += 4;
            }
            else {
                throw new Error(`String index too long: ${index} in file ` + this.fileName);
            }
        }
        else {
            const index = this.stringList.add(string);
            if (index < 16) {
                valueWriter.ubyte = JPType.STR_0 + index;
            }
            else if (index < 0x100) {
                // uint8
                valueWriter.ubyte = JPType.STR8;
                valueWriter.ubyte = index;
                length++;
            }
            else if (index < 0x10000) {
                // unit16
                valueWriter.ubyte = JPType.STR16;
                valueWriter.ushort = index;
                length += 2;
            }
            else if (index < 0x100000000) {
                // unit32
                valueWriter.ubyte = JPType.STR32;
                valueWriter.ushort = index;
                length += 4;
            }
            else {
                throw new Error(`String index too long: ${index} in file ` + this.fileName);
            }
        }
        return length;
    }
    ;
    /**
     * Writes a `null` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeNull(valueWriter) {
        valueWriter.ubyte = JPType.NULL;
        return 1;
    }
    ;
    /**
     * Writes an `undefined` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeUndefined(valueWriter) {
        valueWriter.ubyte = JPType.UNDEFINED;
        return 1;
    }
    ;
    /**
     * Writes a `boolean` true or false to the buffer
     *
     * @param valueWriter - Writer
     * @param object - `true` or `false`
     * @returns The `number` of bytes written
     */
    encodeBoolean(valueWriter, object) {
        if (object === false) {
            valueWriter.ubyte = JPType.BOOL_FALSE;
        }
        else {
            valueWriter.ubyte = JPType.BOOL_TRUE;
        }
        return 1;
    }
    ;
    /**
     * Writes an "finished" byte to the buffer. End the loop when hit if not finished otherwise.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeFinished(valueWriter) {
        valueWriter.ubyte = JPType.FINISHED;
        return 1;
    }
    ;
    /**
     * Writes a "list end" byte to the buffer, useful when pulling loose data and don't want to break the whole loop.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeListEnd(valueWriter) {
        valueWriter.ubyte = JPType.LIST_END;
        return 1;
    }
    ;
    /**
     * Writes a `number` to the buffer . Computes the right byte size base on value.
     *
     * Notes: Use `encodeBigInt64` for `bigint` types.
     *
     * @param valueWriter - Writer
     * @param number - Data to encode
     * @returns The `number` of bytes written
     */
    encodeNumber(valueWriter, number) {
        var length = 1;
        if (Number.isSafeInteger(number)) {
            if (number >= 0) {
                if (number < 0x80) {
                    // positive fixint
                    valueWriter.ubyte = number;
                }
                else if (number < 0x100) {
                    // uint 8
                    valueWriter.ubyte = JPType.UINT_8;
                    valueWriter.ubyte = number;
                    length++;
                }
                else if (number < 0x10000) {
                    // uint 16
                    valueWriter.ubyte = JPType.UINT_16;
                    valueWriter.ushort = number;
                    length += 2;
                }
                else if (number < 0x100000000) {
                    // uint 32
                    valueWriter.ubyte = JPType.UINT_32;
                    valueWriter.uint = number;
                    length += 4;
                }
                else {
                    // uint 64
                    valueWriter.ubyte = JPType.UINT_64;
                    valueWriter.uint64 = number;
                    length += 8;
                }
            }
            else {
                if (number >= -32) {
                    // negative fixint
                    valueWriter.byte = number;
                }
                else if (number >= -128) {
                    // int 8
                    valueWriter.ubyte = JPType.INT_8;
                    valueWriter.byte = number;
                    length++;
                }
                else if (number >= -32768) {
                    // int 16
                    valueWriter.ubyte = JPType.INT_16;
                    valueWriter.int16 = number;
                    length += 2;
                }
                else if (number >= -2147483648) {
                    // int 32
                    valueWriter.ubyte = JPType.INT_32;
                    valueWriter.int32 = number;
                    length += 4;
                }
                else {
                    // int 64
                    valueWriter.ubyte = JPType.INT_64;
                    valueWriter.int64 = number;
                    length += 8;
                }
            }
            return length;
        }
        else {
            return this.encodeNumberAsFloat(valueWriter, number);
        }
    }
    ;
    /**
     * Writes a `bigint` to the buffer. Always written as a 64 bit value.
     *
     * @param valueWriter - Writer
     * @param bigint - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBigInt64(valueWriter, bigint) {
        var length = 0;
        if (bigint >= BigInt(0)) {
            // uint 64
            valueWriter.ubyte = JPType.UINT_64;
            length++;
            valueWriter.uint64 = bigint;
            length += 8;
        }
        else {
            // int 64
            valueWriter.ubyte = JPType.INT_64;
            length++;
            valueWriter.int64 = bigint;
            length += 8;
        }
        return length;
    }
    ;
    encodeStringHeader(byteLength) {
        var length = 1;
        if (this.strWriter == null) {
            throw new Error("Didn't create writer. " + this.fileName);
        }
        if (byteLength < 16) {
            // fixstr
            this.strWriter.ubyte = JPType.STR_0 + byteLength;
        }
        else if (byteLength < 0x100) {
            // str 8
            this.strWriter.ubyte = JPType.STR8;
            this.strWriter.ubyte = byteLength;
            length++;
        }
        else if (byteLength < 0x10000) {
            // str 16
            this.strWriter.ubyte = JPType.STR16;
            this.strWriter.uint16 = byteLength;
            length += 2;
        }
        else if (byteLength < 0x100000000) {
            // str 32
            this.strWriter.ubyte = JPType.STR32;
            this.strWriter.uint32 = byteLength;
            length += 4;
        }
        else {
            throw new Error(`Too long string: ${byteLength} bytes in UTF-8 in file ` + this.fileName);
        }
        return length;
    }
    ;
    writeString(object) {
        if (this.strWriter == null) {
            throw new Error("Didn't create writer. " + this.fileName);
        }
        const encoder = new TextEncoder();
        const encodedString = encoder.encode(object);
        const byteLength = encodedString.length;
        var length = this.encodeStringHeader(byteLength);
        this.strWriter.string(object, { length: byteLength });
        return length + byteLength;
    }
    ;
    writeStringsData() {
        const array = this.stringList.getValues();
        const size = array.length;
        if (this.strWriter == null) {
            throw new Error("Didn't create writer. " + this.fileName);
        }
        if (size < 16) {
            // fixarray
            this.strWriter.ubyte = JPType.ARRAY_0 + size;
        }
        else if (size < 0x100) {
            // uint8
            this.strWriter.ubyte = JPType.ARRAY8;
            this.strWriter.ubyte = size;
        }
        else if (size < 0x10000) {
            // array 16
            this.strWriter.ubyte = JPType.ARRAY16;
            this.strWriter.ushort = size;
        }
        else if (size < 0x100000000) {
            // array 32
            this.strWriter.ubyte = JPType.ARRAY32;
            this.strWriter.uint32 = size;
        }
        else {
            throw new Error(`String array too large: ${size} in file ` + this.fileName);
        }
        for (let i = 0; i < size; i++) {
            const el = array[i];
            this.writeString(el);
        }
    }
    ;
    encodeNumberAsFloat(valueWriter, object) {
        var length = 1;
        if (isFloat32Safe(object)) {
            // float 32
            valueWriter.ubyte = JPType.FLOAT32;
            valueWriter.float = object;
            length += 4;
        }
        else {
            // float 64
            valueWriter.ubyte = JPType.FLOAT64;
            valueWriter.dfloat = object;
            length += 8;
        }
        return length;
    }
    ;
    ////////////
    //  EXTS  //
    ////////////
    encodeExtension(valueWriter, ext) {
        const size = ext.data.length;
        var length = size;
        if (size < 0x100) {
            // ext 8
            valueWriter.ubyte = JPType.EXT8;
            valueWriter.ubyte = size;
            length += 2;
        }
        else if (size < 0x10000) {
            // ext 16
            valueWriter.ubyte = JPType.EXT16;
            valueWriter.ushort = size;
            length += 3;
        }
        else if (size < 0x100000000) {
            // ext 32
            valueWriter.ubyte = JPType.EXT32;
            valueWriter.uint32 = size;
            length += 5;
        }
        else {
            throw new Error(`Too large extension object: ${size} in file ` + this.fileName);
        }
        valueWriter.ubyte = ext.type;
        length++;
        valueWriter.overwrite(ext.data, true);
        return length;
    }
    ;
    /**
     * Writes a `Map` to the buffer as `Map<key, value>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeMap(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        // Note: length here is the array size of Map, not the buffer size
        var length = 1;
        const keys = [...object.keys()];
        const size = object.size;
        if (size < 0x100) {
            valueWriter.ubyte = JPType.EXT8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            throw new Error(`Too large Set length: ${size} in file ` + this.fileName);
        }
        this.valueWriter.ubyte = JPExtType.Maps;
        length++;
        for (const key of keys) {
            const value = object.get(key);
            length += this.doEncode(valueWriter, key, depth + 1); // keys can have any type here
            //this.valueWriter.ubyte = JPType.LIST_END; length++;
            length += this.doEncode(valueWriter, value, depth + 1);
            //this.valueWriter.ubyte = JPType.LIST_END; length++;
        }
        return length;
    }
    ;
    /**
     * Writes a `Set` to the buffer as `Set<type>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeSet(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        // Note: length here is the array size of Set, not the buffer size
        var length = 1;
        const size = object.size;
        if (size < 0x100) {
            valueWriter.ubyte = JPType.EXT8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            throw new Error(`Too large Set length: ${size} in file ` + this.fileName);
        }
        this.valueWriter.ubyte = JPExtType.Sets;
        for (const item of object) {
            length += this.doEncode(valueWriter, item, depth + 1);
            // this.valueWriter.ubyte = JPType.LIST_END; length++;
        }
        return length;
    }
    ;
    /**
     * Writes a `symbol` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeSymbol(valueWriter, object) {
        const extBuffer = new BiWriter(Buffer.alloc(512));
        const keyCheck = Symbol.keyFor(object);
        const global = !!keyCheck;
        var key = keyCheck ?? object.description;
        key = key ?? "";
        var length = 0;
        length += this.encodeBoolean(extBuffer, global);
        length += this.encodeString(extBuffer, key, false);
        extBuffer.trim();
        if (length < 0x100) {
            valueWriter.ubyte = JPType.EXT8;
            valueWriter.ubyte = length;
        }
        else if (length < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;
            valueWriter.ushort = length;
        }
        else if (length < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;
            valueWriter.uint = length;
        }
        else {
            throw new Error(`Too large Symbol length: ${length} in file ` + this.fileName);
        }
        valueWriter.ubyte = JPExtType.Symbol;
        valueWriter.overwrite(extBuffer.return, true);
        return length;
    }
    ;
    /**
     * Writes a `RegEx` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeRegEx(valueWriter, object) {
        const extBuffer = new BiWriter(Buffer.alloc(512));
        const src = object.source;
        const flags = object.flags;
        var length = 0;
        length += this.encodeString(extBuffer, src, false);
        length += this.encodeString(extBuffer, flags, false);
        extBuffer.trim();
        if (length < 0x100) {
            valueWriter.ubyte = JPType.EXT8;
            valueWriter.ubyte = length;
        }
        else if (length < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;
            valueWriter.ushort = length;
        }
        else if (length < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;
            valueWriter.uint = length;
        }
        else {
            throw new Error(`Too large RegEx length: ${length} in file ` + this.fileName);
        }
        valueWriter.ubyte = JPExtType.RegEx;
        valueWriter.overwrite(extBuffer.return, true);
        return length;
    }
    ;
    /**
     * Writes a `TypedArray` or `Buffer` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBinary(valueWriter, object) {
        var length = 1;
        const byteLength = object.byteLength;
        if (byteLength < 0x100) {
            valueWriter.ubyte = JPType.EXT8;
            valueWriter.ubyte = byteLength;
            length++;
        }
        else if (byteLength < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;
            valueWriter.ushort = byteLength;
            length += 2;
        }
        else if (byteLength < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;
            valueWriter.uint32 = byteLength;
            length += 4;
        }
        else {
            throw new Error(`Buffer ranged too large. ${byteLength} in file ` + this.fileName);
        }
        if (object instanceof Buffer) {
            valueWriter.ubyte = JPExtType.Buffer;
            length++;
            valueWriter.overwrite(object, true);
            length += object.length;
        }
        else {
            if (object instanceof Int8Array) {
                valueWriter.ubyte = JPExtType.Int8Array;
            }
            else if (object instanceof Uint8Array) {
                valueWriter.ubyte = JPExtType.Uint8Array;
            }
            else if (object instanceof Uint8ClampedArray) {
                valueWriter.ubyte = JPExtType.Uint8ClampedArray;
            }
            else if (object instanceof Int16Array) {
                valueWriter.ubyte = JPExtType.Int16Array;
            }
            else if (object instanceof Uint16Array) {
                valueWriter.ubyte = JPExtType.Uint16Array;
            }
            else if (object instanceof Int32Array) {
                valueWriter.ubyte = JPExtType.Int32Array;
            }
            else if (object instanceof Uint32Array) {
                valueWriter.ubyte = JPExtType.Uint32Array;
            }
            else if (object instanceof Float32Array) {
                valueWriter.ubyte = JPExtType.Float32Array;
                //} else if(object instanceof Float16Array){
                // not active yet
                //    valueWriter.ubyte = JPExtType.Float16Array;
            }
            else if (object instanceof Float64Array) {
                valueWriter.ubyte = JPExtType.Float64Array;
            }
            else if (object instanceof BigInt64Array) {
                valueWriter.ubyte = JPExtType.BigInt64Array;
            }
            else if (object instanceof BigUint64Array) {
                valueWriter.ubyte = JPExtType.BigUint64Array;
            }
            else {
                throw new Error('Unknown Buffer type in file ' + this.fileName);
            }
            length++;
            const uData = new Uint8Array(object.buffer);
            valueWriter.overwrite(uData, true);
            length += uData.length;
        }
        return length;
    }
    ;
    /**
     * Writes a `Date` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeDate(valueWriter, object) {
        const TIMESTAMP32_MAX_SEC = 0x100000000 - 1; // 32-bit unsigned int
        const TIMESTAMP64_MAX_SEC = 0x400000000 - 1; // 34-bit unsigned int
        const msec = object.getTime();
        const _sec = Math.floor(msec / 1e3);
        const _nsec = (msec - _sec * 1e3) * 1e6;
        // Normalizes { sec, nsec } to ensure nsec is unsigned.
        const nsecInSec = Math.floor(_nsec / 1e9);
        const sec = _sec + nsecInSec;
        const nsec = _nsec - nsecInSec * 1e9;
        valueWriter.ubyte = JPType.EXT8;
        if (sec >= 0 && nsec >= 0 && sec <= TIMESTAMP64_MAX_SEC) {
            // Here sec >= 0 && nsec >= 0
            if (nsec === 0 && sec <= TIMESTAMP32_MAX_SEC) {
                // timestamp 32 = { sec32 (unsigned) }
                valueWriter.ubyte = 4;
                valueWriter.ubyte = JPExtType.Date;
                valueWriter.uint32 = sec >>> 0;
                return 7;
            }
            else {
                valueWriter.ubyte = 8;
                valueWriter.ubyte = JPExtType.Date;
                // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
                const secHigh = sec / 0x100000000;
                const secLow = sec & 0xffffffff;
                // nsec30 | secHigh2
                valueWriter.uint32 = ((nsec << 2) | (secHigh & 0x3)) >>> 0;
                // secLow32
                valueWriter.uint32 = secLow >>> 0;
                return 11;
            }
        }
        else {
            // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
            valueWriter.ubyte = 12;
            valueWriter.ubyte = JPExtType.Date;
            valueWriter.uint32 = nsec >>> 0;
            valueWriter.int64 = sec;
            return 15;
        }
    }
    ;
    //////////////
    // FINALIZE //
    //////////////
    /**
     * Creates headers buffer.
     *
     * Note: Must have compressed or encrypted data already.
     *
     * Should be the last thing before completeing the buffer
     *
     * @param {endian} endian
     * @returns
     */
    buildHeader(endian) {
        if (endian) {
            this.endian = endian;
        }
        if (BigInt(this.HEADER_SIZE) + this.DATA_SIZE > BigInt(0x100000000)) {
            this.LargeFile = 1;
        }
        const bw = new BiWriter(Buffer.alloc(this.HEADER_SIZE));
        bw.endian = this.endian;
        bw.uint16 = this.MAGIC;
        bw.uint8 = this.VERSION_MAJOR;
        bw.uint8 = this.VERSION_MINOR;
        bw.uint8 = this.HEADER_SIZE;
        bw.bit1 = this.LargeFile;
        bw.bit1 = this.Compressed;
        bw.bit1 = this.Crc32;
        bw.bit1 = this.Encrypted;
        if (this.Encrypted == 0)
            this.EncryptionExcluded = 0;
        bw.bit1 = this.EncryptionExcluded;
        bw.bit1 = this.KeyStripped;
        bw.bit1 = 0; // FLAG6
        bw.bit1 = 0; // FLAG7
        bw.uint8 = 0; // RESV_6 FLAG8-15
        bw.uint8 = 0; // RESV_7 FLAG16-23
        bw.uint64 = this.VALUE_SIZE;
        bw.uint64 = this.STR_SIZE;
        bw.uint64 = this.DATA_SIZE;
        if (this.Crc32) {
            bw.uint32 = this.CRC32;
        }
        if (this.Encrypted && !this.EncryptionExcluded) {
            bw.uint32 = this.encryptionKey;
        }
        bw.trim();
        this.headerBuffer = bw.get;
        return this.headerBuffer;
    }
    ;
    finalizeBuffers() {
        if (this.strWriter == null || this.valueWriter == null) {
            throw new Error("Didn't create writers. " + this.fileName);
        }
        if (!this.useStream) {
            this.valueWriter.trim();
            this.strWriter.trim();
            const stringData = this.strWriter.data;
            this.valueWriter.overwrite(stringData, true);
            this.compWriter = this.valueWriter;
            this.compWriter.trim();
        }
        else {
            this.valueWriter.trim();
            this.strWriter.trim();
            const compWriter = new BiWriterStream(this.fileName + ".comp");
            compWriter.overwrite(this.valueWriter.read(0, this.valueWriter.size), true);
            compWriter.overwrite(this.strWriter.read(0, this.strWriter.size), true);
            this.valueWriter.deleteFile();
            this.strWriter.deleteFile();
            this.compWriter = compWriter;
            this.compWriter.trim();
        }
        this.DATA_SIZE = BigInt(this.compWriter.size);
        if (this.Crc32) {
            this.CRC();
        }
        if (this.Compressed) {
            this.compress();
            this.DATA_SIZE = BigInt(this.compWriter.size);
        }
        if (this.Encrypted) {
            this.encrypt(this.EncryptionExcluded ? true : false, this.encryptionKey == 0 ? undefined : this.encryptionKey);
        }
    }
    ;
    /**
     * Can stip or include the key value in file
     *
     * Can also set your own key.
     *
     * @param {boolean?} EncryptionExcluded - remove key from file
     * @param {number?} Encryptionkey - 32 bit number
     */
    encrypt(EncryptionExcluded, Encryptionkey) {
        this.Encrypted = 1;
        this.EncryptionExcluded = EncryptionExcluded ? 1 : 0;
        if (this.compWriter == null) {
            throw new Error("Writer not created for encryption. " + this.fileName);
        }
        const cypter = new Crypt(Encryptionkey);
        this.encryptionKey = cypter.key;
        if (!this.useStream) {
            const compBuffer = cypter.encrypt(this.compWriter.data);
            this.compWriter = new BiWriter(compBuffer);
            return this.compWriter.size;
        }
        else {
            const CHUNK_SIZE = 16; // 16 bytes at a time
            this.compWriter.gotoStart();
            var data;
            var buffer = Buffer.alloc(0);
            let bytesToProcess = Number(this.DATA_SIZE);
            let bytesStart = 0;
            let bytesRead = 0;
            let amount = Math.ceil(this.compWriter.size / CHUNK_SIZE);
            for (let index = 0; index < amount; index++) {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                buffer = this.compWriter.read(bytesStart, bytesRead);
                if (index == (amount - 1)) {
                    data = cypter.encrypt_block(buffer, true);
                }
                else {
                    data = cypter.encrypt_block(buffer);
                }
                if (data.length != 0) {
                    this.compWriter.overwrite(data, true);
                }
                bytesStart += buffer.length;
                bytesToProcess -= buffer.length;
            }
            data = cypter.encrypt_final();
            if (data.length != 0) {
                this.compWriter.overwrite(data, true);
            }
            this.compWriter.trim();
            return this.compWriter.size;
        }
    }
    ;
    /**
     * Compresses data
     */
    compress() {
        this.Compressed = 1;
        if (this.compWriter == null) {
            throw new Error("Writer not created for compression. " + this.fileName);
        }
        if (!this.useStream) {
            this.compWriter.gotoStart();
            const compBuffer = deflateBuffer(this.compWriter);
            this.compWriter = new BiWriter(compBuffer);
            this.compWriter.gotoEnd();
        }
        else {
            const temp = this.fileName + ".comp.tmp";
            const tempcompWriter = new BiWriterStream(temp);
            tempcompWriter.open();
            deflateFileSync(this.compWriter, tempcompWriter);
            this.compWriter.gotoStart();
            this.compWriter.overwrite(tempcompWriter.read(0, tempcompWriter.offset), true);
            this.compWriter.trim();
            tempcompWriter.deleteFile();
        }
    }
    ;
    /**
     * Creates CRC hash
     */
    CRC() {
        this.Crc32 = 1;
        if (this.compWriter == null) {
            throw new Error("Writer not created for CRC. " + this.fileName);
        }
        if (!this.useStream) {
            const data = this.compWriter.data;
            this.CRC32 = CRC32(data, 0) >>> 0;
            return;
        }
        else {
            let crc = 0;
            const CHUNK_SIZE = 0x2000; // 8192 bytes
            for (let position = 0; position <= this.compWriter.size;) {
                const buffer = this.compWriter.read(position, Math.min(CHUNK_SIZE, this.compWriter.size - position));
                if (buffer.length == 0)
                    break;
                crc = CRC32(buffer, crc);
                position += buffer.length;
            }
            this.CRC32 = crc >>> 0;
        }
    }
    ;
}

export { JPDecode, JPEncode, JPExtData, JPExtensionCodec };
//# sourceMappingURL=index.esm.js.map
