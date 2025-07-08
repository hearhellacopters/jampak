import fs from 'fs';
import crypto from 'node:crypto';
import { BiWriter, BiReaderStream, BiReader, BiWriterStream } from 'bireader';
import zlib from 'zlib';
import { constants } from 'node:buffer';

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
    finished = false;
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
        this.keyBuff = keyBuff.data;
        this.ivBuffer = iv.data;
    }
    ;
    encrypt(data) {
        if (this.cipher == undefined) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return Buffer.concat([this.cipher.update(data), this.cipher.final()]);
    }
    ;
    decrypt(data) {
        if (this.decipher == undefined) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return Buffer.concat([this.decipher.update(data), this.decipher.final()]);
    }
    ;
    encrypt_block(data) {
        if (this.cipher == undefined) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        if (data.length < 16) {
            this.finished = true;
            return Buffer.concat([this.cipher.update(data), this.cipher.final()]);
        }
        return this.cipher.update(data);
    }
    ;
    decrypt_block(data) {
        if (this.decipher == undefined) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        if (data.length < 16) {
            this.finished = true;
            return Buffer.concat([this.decipher.update(data), this.decipher.final()]);
        }
        return this.decipher.update(data);
    }
    ;
    encrypt_final() {
        if (this.cipher == undefined) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        if (this.finished == true) {
            return Buffer.alloc(0);
        }
        return this.cipher.final();
    }
    ;
    decrypt_final() {
        if (this.decipher == undefined) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        if (this.finished == true) {
            return Buffer.alloc(0);
        }
        this.finished = true;
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

var version = "1.0.1";
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
                throw new Error("No value reader set.");
            }
            this.stringsList = this.createStringList();
            const object = this.doDecodeSync(this.valueReader);
            if (this.tempCreated) {
                this.valueReader.deleteFile();
                this.valueReader.close();
            }
            if (this.makeJSON) {
                return JSON.parse(JSON.stringify(object));
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
            throw new Error(`File magics incorrect. Expecting 0x504A or 0x4A50, but got 0x${MAGICS.toString(16).padStart(4, "0")}`);
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
            console.warn(`File was encoded in a more advanced version of this package which may cause issues. Package: ${VERSION_NUMBER} - File: ${V_NUMBER}`);
        }
        if (this.LargeFile && (br.size > MAX_BUFFER || (this.STR_SIZE + this.VALUE_SIZE) > MAX_BUFFER)) {
            this.useStream = true;
        }
        if (this.EncryptionExcluded && this.encryptionKey == 0) {
            throw new Error('The encryption key is not included in the file and the key was not set in the decoder. Can not decode.');
        }
        if (this.KeyStripped && this.keysArray.length == 0) {
            throw new Error('The keysArray was removed from the file and not set in the decoder. Can not decode.');
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
                this.decrypt(compWriter);
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
                    console.warn(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32} but got ${crc}.`);
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
                console.warn(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${totalSize}.`);
            }
        }
        else {
            if (this.buffer == null) {
                throw new Error("Buffer not set");
            }
            this.fileReader = new BiReader(this.buffer);
            this.fileReader.endian = this.endian;
            this.fileReader.goto(this.HEADER_SIZE);
            var decomBuffer = this.buffer.subarray(this.HEADER_SIZE, this.buffer.length);
            this.compReader = new BiReader(decomBuffer);
            this.compReader.endian = this.endian;
            if (this.Encrypted) {
                decomBuffer = this.decrypt(null, decomBuffer);
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
                    console.warn(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32} but got ${crc}.`);
                }
            }
            if (this.VALUE_SIZE + this.STR_SIZE != BigInt(this.compReader.size)) {
                console.warn(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${this.compReader.size}.`);
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
            throw new Error("string reader not set.");
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
                throw new Error(`Invalid data in string area. 0x${headByte.toString(16).padStart(2, "0")}`);
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
                    throw new Error('Should only have an array in the string data, found type ' + state.type);
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
            throw new Error("Value reader not set.");
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
                    console.warn(`Did not find key value for index ` + index);
                }
                object = this.keysArray[index];
            }
            else if (headByte < JPType.NULL) {
                //fixstr
                const index = headByte - 0xB0;
                if (this.stringsList[index] === undefined) {
                    console.warn(`Did not find string value for index ` + index);
                    console.debug(this.stringsList);
                }
                object = this.stringsList[index];
            }
            else if (headByte == JPType.NULL) {
                object = null;
            }
            else if (headByte == JPType.UNDEFINED) {
                object = undefined;
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
                    console.warn(`Did not find key value for index ` + index);
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
                    console.warn(`Did not find string value for index ` + index);
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
                    if (size !== 0) {
                        this.pushMapState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Map();
                    }
                }
                else if (type == JPExtType.Sets) {
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
                throw new Error(`Outside of index error 0x${headByte.toString(16).padStart(2, "0")}`);
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
                        throw new Error("The key __proto__ is not allowed");
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
                        throw new Error("The key __proto__ is not allowed");
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
            throw new Error("Value reader not set.");
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
                console.warn(`Did not find string value for index ` + index);
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
                // bool and string
                const global = valueReader.ubyte == JPType.BOOL_TRUE ? true : false;
                var headByte = valueReader.ubyte;
                const key = this.readString(headByte);
                retValue = global ? Symbol.for(key) : Symbol(key);
                this.symbolList.push(retValue);
                break;
            case JPExtType.RegEx:
                // two strings
                const source = this.readString(valueReader.ubyte);
                const flags = this.readString(valueReader.ubyte);
                retValue = new RegExp(source, flags);
                break;
            case JPExtType.Maps:
                // handled before
                break;
            case JPExtType.Sets:
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
                        throw new Error(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${br.size}`);
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
    decrypt(br, buffer) {
        const cypter = new Crypt(this.encryptionKey);
        if (!this.useStream) {
            if (buffer == null) {
                throw new Error("Buffer to decrypt not set.");
            }
            return cypter.decrypt(buffer);
        }
        else {
            const CHUNK_SIZE = 16;
            br.open();
            br.gotoStart();
            var buff = Buffer.alloc(0);
            let bytesToProcess = Number(this.DATA_SIZE);
            let bytesStart = 0;
            let bytesRead = 0;
            do {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                if (bytesRead > 0) {
                    buff = br.read(bytesStart, bytesRead);
                    bytesToProcess -= buff.length;
                    const data = cypter.decrypt_block(buff);
                    if (data.length != 0) {
                        br.overwrite(data, true);
                    }
                    bytesStart += buff.length;
                }
                else {
                    const data = cypter.decrypt_final();
                    if (data.length != 0) {
                        br.overwrite(data, true);
                    }
                    bytesToProcess = 0;
                }
            } while (bytesToProcess !== 0);
            if (!cypter.finished) {
                const data = cypter.decrypt_final();
                if (data.length != 0) {
                    br.overwrite(data, true);
                }
            }
            br.trim();
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
                throw new Error("Didn't create writers");
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
                throw new Error("Didn't create writer.");
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
                throw new Error(`Unrecognized object: ${Object.prototype.toString.apply(object)}`);
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
            throw new Error(`Too large map object: ${size}`);
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
            throw new Error(`Too large array: ${size}`);
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
                throw new Error(`String index too long: ${index}`);
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
                throw new Error(`String index too long: ${index}`);
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
            throw new Error("Didn't create writer.");
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
            throw new Error(`Too long string: ${byteLength} bytes in UTF-8`);
        }
        return length;
    }
    ;
    writeString(object) {
        if (this.strWriter == null) {
            throw new Error("Didn't create writer.");
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
            throw new Error("Didn't create writer.");
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
            throw new Error(`String array too large: ${size}`);
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
            throw new Error(`Too large extension object: ${size}`);
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
            throw new Error(`Too large Set length: ${size}`);
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
            throw new Error(`Too large Set length: ${size}`);
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
            throw new Error(`Too large Symbol length: ${length}`);
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
            throw new Error(`Too large RegEx length: ${length}`);
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
            throw new Error('Buffer ranged too large. ' + byteLength);
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
                throw new Error('Unknown Buffer type.');
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
            throw new Error("Didn't create writers.");
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
        if (this.Crc32) {
            this.CRC();
        }
        if (this.Compressed) {
            this.compress();
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
            throw new Error("Writer not created for encryption.");
        }
        const cypter = new Crypt(Encryptionkey);
        this.encryptionKey = cypter.key;
        if (!this.useStream) {
            const compBuffer = cypter.encrypt(this.compWriter.data);
            this.compWriter = new BiWriter(compBuffer);
            if (this.HEADER_SIZE + this.compWriter.size > MAX_BUFFER) {
                this.LargeFile = 1;
            }
            this.DATA_SIZE = this.compWriter.size;
            return this.DATA_SIZE;
        }
        else {
            const CHUNK_SIZE = 16; // 16 bytes at a time
            this.compWriter.gotoStart();
            var buffer = Buffer.alloc(0);
            let bytesToProcess = Number(this.DATA_SIZE);
            let bytesStart = 0;
            let bytesRead = 0;
            do {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                if (bytesRead > 0) {
                    buffer = this.compWriter.read(bytesStart, bytesRead);
                    bytesToProcess -= buffer.length;
                    const data = cypter.encrypt_block(buffer);
                    if (data.length != 0) {
                        this.compWriter.overwrite(data, true);
                    }
                    bytesStart += buffer.length;
                }
                else {
                    const data = cypter.encrypt_final();
                    if (data.length != 0) {
                        this.compWriter.overwrite(data, true);
                    }
                    bytesToProcess = 0;
                }
            } while (bytesToProcess !== 0);
            if (!cypter.finished) {
                const data = cypter.encrypt_final();
                if (data.length != 0) {
                    this.compWriter.overwrite(data, true);
                }
            }
            this.DATA_SIZE = this.compWriter.size;
            return this.DATA_SIZE;
        }
    }
    ;
    /**
     * Compresses data
     */
    compress() {
        this.Compressed = 1;
        if (this.compWriter == null) {
            throw new Error("Writer not created for compression.");
        }
        if (!this.useStream) {
            this.compWriter.gotoStart();
            const compBuffer = deflateBuffer(this.compWriter);
            this.compWriter = new BiWriter(compBuffer);
            this.compWriter.gotoEnd();
            this.DATA_SIZE = this.compWriter.size;
        }
        else {
            const HEADER_SIZE = this.HEADER_SIZE;
            const temp = this.fileName + ".comp.tmp";
            const tempcompWriter = new BiWriterStream(temp);
            tempcompWriter.open();
            deflateFileSync(this.compWriter, tempcompWriter);
            this.compWriter.gotoStart();
            this.compWriter.overwrite(tempcompWriter.read(0, tempcompWriter.offset), true);
            this.compWriter.trim();
            this.DATA_SIZE = this.compWriter.size;
            tempcompWriter.deleteFile();
            if (HEADER_SIZE + this.compWriter.size > MAX_BUFFER) {
                this.LargeFile = 1;
            }
        }
    }
    ;
    /**
     * Creates CRC hash
     */
    CRC() {
        this.Crc32 = 1;
        if (this.compWriter == null) {
            throw new Error("Writer not created for CRC.");
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
