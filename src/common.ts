import fs from "fs";
import zlib from 'zlib';
import { constants as bufferConstants } from "node:buffer";
import {
    BiReader,
    BiWriter,
    BiReaderAsync,
    BiWriterAsync
} from 'bireader';
import { JPExtensionCodecType } from "./ext.js";
import pack from '../package.json';

export const GROWTHINCREMENT_DEFAULT = 0x1000000;

type reader = BiReader<Buffer, any> | BiWriter<Buffer, any>;

type readerAsync = BiReaderAsync<Buffer, any> | BiWriterAsync<Buffer, any>;

/**
 * Get build version string.
 * 
 * @returns {{VERSION_MAJOR: ubyte, VERSION_MINOR: ubyte}}
 */
function GetVer(): { VERSION_MAJOR: ubyte, VERSION_MINOR: ubyte } {
    const ver = /(\d+)(\.)(\d+)(\.)(\d+)/g.exec(pack.version);

    return {
        VERSION_MAJOR: parseInt(ver ? ver[1] : "0"),

        VERSION_MINOR: parseInt(ver ? ver[3] : "0"),
    };
};

export const {
    /**
     * Build verion number to check the file creation params
     */
    VERSION_MAJOR,
    /**
     * Build verion number to check the file creation params
     */
    VERSION_MINOR
} = GetVer();

/**
 * Build verion number to check the file creation params
 */
export const VERSION_NUMBER: float32 = parseFloat(`${VERSION_MAJOR}.${VERSION_MINOR}`);

/**
 * Max Buffer size.
 * 
 * @returns {number}
 */
function MAX_LENGTH(): number {
    return bufferConstants.MAX_LENGTH;
};

/**
 * Max Buffer size for this system.
 */
export const MAX_BUFFER = MAX_LENGTH() || 0x100000000;

export function isFloat32Safe(value: number): boolean {
    if (!Number.isFinite(value)) return true; // Infinity, -Infinity, NaN all store fine

    const f32 = new Float32Array(1);

    f32[0] = value;

    return f32[0] === value;
}

/**
 * 512kb zip chunks
 */
const CHUNK_SIZE = 512 * 1024;

/**
 * Peak starting bytes of a file.
 * 
 * @param {string} filePath 
 * @param {number} numBytes 
 * @returns {Buffer}
 */
export function peakBytesSync(filePath: string, numBytes: number): Buffer {
    const fd = fs.openSync(filePath, 'r');

    const buffer = Buffer.alloc(numBytes);

    try {
        fs.readSync(fd, buffer, 0, numBytes, 0);
    } finally {
        fs.closeSync(fd);
    }

    return buffer;
};

/**
 * Checks if a file exisits
 * 
 * @param {string} filePath 
 * @returns {boolean}
 */
export function fileExists(filePath: string): boolean{
    try {
        fs.accessSync(filePath, fs.constants.F_OK);

        return true;  // File exists
    } catch (error) {
        return false;
    }
};

/**
 * Compress a file using Deflate, framed with [length][chunk] blocks.
 */
export function deflateFileSync(inWriter: BiWriter<any, any>, outWriter: BiWriter<any, any>): void {
    inWriter.open();

    outWriter.open();

    let bytesToProcess = inWriter.size;

    let bytesStart = 0;

    let bytesRead = 0;

    do {
        bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);

        if (bytesRead > 0) {
            const chunk = inWriter.subarray(bytesStart, bytesRead, true);

            const compressed = zlib.deflateSync(chunk);

            outWriter.uint32le = compressed.length;

            outWriter.overwrite(compressed, outWriter.offset, true);

            bytesToProcess -= bytesRead;

            bytesStart += bytesRead;
        }
    } while (bytesRead === CHUNK_SIZE);
};

/**
 * Decompress a framed deflate-compressed file.
 */
export function inflateFileSync(inReader: BiReader<any, any>, outWriter: BiWriter<any, any>): void {
    inReader.open();

    outWriter.open();

    let bytesToProcess = inReader.size;

    let bytesStart = 0;

    let bytesRead = 0;

    do {
        bytesRead = inReader.uint32;

        bytesStart += 4;

        if (bytesRead > 0) {
            const chunk = inReader.subarray(bytesStart, bytesRead, true);

            bytesToProcess -= chunk.length;

            const uncompressed = zlib.inflateSync(chunk);

            outWriter.overwrite(uncompressed, outWriter.offset, true);

            bytesStart += bytesRead;
        }
    } while (bytesStart < bytesToProcess);
};

/**
 * Decompress a framed deflate-compressed file.
 */
export async function inflateFileAsync(inReader: BiReaderAsync<any, any>, outWriter: BiWriterAsync<any, any>): Promise<void> {
    await inReader.open();

    await outWriter.open();

    let bytesToProcess = inReader.size;

    let bytesStart = 0;

    let bytesRead = 0;

    do {
        bytesRead = await inReader.uint32();

        bytesStart += 4;

        if (bytesRead > 0) {
            const chunk = await inReader.subarray(bytesStart, bytesRead, true);

            bytesToProcess -= chunk.length;

            const uncompressed = zlib.inflateSync(chunk);

            await outWriter.overwrite(uncompressed, outWriter.offset, true);

            bytesStart += bytesRead;
        }
    } while (bytesStart < bytesToProcess);
};

/**
 * Compress a Buffer using Deflate, framed with [length][chunk] blocks.
 */
export function deflateBuffer(inWriter: reader): Buffer {
    let bytesToProcess = inWriter.size;

    let bytesStart = 0;

    let bytesRead = 0;

    const buffers: Buffer[] = [];

    do {
        bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);

        if (bytesRead > 0) {
            const chunk = inWriter.subarray(bytesStart, bytesRead, true);

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
};

/**
 * Compress a Buffer using Deflate, framed with [length][chunk] blocks.
 */
export async function deflateBufferAsync(inWriter: readerAsync): Promise<Buffer> {
    let bytesToProcess = inWriter.size;

    let bytesStart = 0;

    let bytesRead = 0;

    const buffers: Buffer[] = [];

    do {
        bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);

        if (bytesRead > 0) {
            const chunk = await inWriter.subarray(bytesStart, bytesRead, true);

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
};

/**
 * Decompress a framed deflate-compressed buffer.
 */
export function inflateBuffer(bw: reader): Buffer {
    const startingOff = bw.offset;

    const size = bw.size;

    const totalBuffer = size - startingOff;

    let bytesRead = 0;

    const buffers: Buffer[] = [];

    while (bytesRead < totalBuffer) {
        const chunkLen = bw.readUInt32LE(); bytesRead += 4;

        const compressed = bw.extract(chunkLen); bytesRead += chunkLen;

        const decompressed = zlib.inflateSync(compressed);

        buffers.push(decompressed);
    }

    return Buffer.concat(buffers);
};

/**
 * Decompress a framed deflate-compressed buffer.
 */
export async function inflateBufferAsync(bw: readerAsync): Promise<Buffer> {
    const startingOff = bw.offset;

    const size = bw.size;

    const totalBuffer = size - startingOff;

    let bytesRead = 0;

    const buffers: Buffer[] = [];

    while (bytesRead < totalBuffer) {
        const chunkLen = await bw.readUInt32LE(); bytesRead += 4;

        const compressed = await bw.extract(chunkLen); bytesRead += chunkLen;

        const decompressed = zlib.inflateSync(compressed);

        buffers.push(decompressed);
    }

    return Buffer.concat(buffers);
};

export function isArrayBufferLike(buffer: unknown): buffer is ArrayBufferLike {
    return (
        buffer instanceof ArrayBuffer || (typeof SharedArrayBuffer !== "undefined" && buffer instanceof SharedArrayBuffer)
    );
};

export function ensureBuffer(
    buffer: Buffer | ArrayLike<number> | Uint8Array<ArrayBufferLike> | ArrayBufferView | ArrayBufferLike,
): Buffer {
    if (buffer instanceof Buffer) {
        return buffer;
    } else if (buffer instanceof Uint8Array) {
        return Buffer.from(buffer);
    } else if (ArrayBuffer.isView(buffer)) {
        return Buffer.from(buffer.buffer);
    } else if (isArrayBufferLike(buffer)) {
        return Buffer.from(buffer);
    } else {
        // ArrayLike<number>
        return Buffer.from(buffer);
    }
};

export type endian = "little" | "big";

export type BigValue = bigint | number;

/**
 * Between 0 and 1.
 */
export type bit = 1 | 0;
/**
 * Between 0 and 255.
 */
export type ubyte = number;
/**
 * Between -128 to 127.
 */
export type byte = number;
/**
 * Between 0 and 255.
 */
export type uint8 = number;
/**
 * Between -128 to 127.
 */
export type int8 = number;
/**
 * Between 0 to 65535.
 */
export type uint16 = number;
/**
 * Between -32768 to 32767.
 */
export type int16 = number;
/**
 * Between 0 to 4294967295.
 */
export type uint32 = number;
/**
 * Between -2147483648 to 2147483647
 */
export type int32 = number;
/**
 * Between 0  to 18446744073709551615
 */
export type uint64 = bigint;
/**
 * Between -9223372036854775808 to 9223372036854775807
 */
export type int64 = bigint;
/**
 * Between -3.40282347E+38 to -1.17549435E-38
 */
export type float32 = number;
/**
 * Between -1.7977 x 10^308 to -2.2251 x 10^-308
 * 
 * And between 2.2251 x 10^-308 to 1.7977 x 10^308
 */
export type float64 = number;

/**
 * Internal index for values.
 */
export enum JPType {
    // 0x00 - 0x7F positive fixint 
    OBJECT_0 = 0x80, // = {} length
    OBJECT_1 = 0x81,
    OBJECT_2 = 0x82,
    OBJECT_3 = 0x83,
    OBJECT_4 = 0x84,
    OBJECT_5 = 0x85,
    OBJECT_6 = 0x86,
    OBJECT_7 = 0x87,
    OBJECT_8 = 0x88,
    OBJECT_9 = 0x89,
    OBJECT_10 = 0x8A,
    OBJECT_11 = 0x8B,
    OBJECT_12 = 0x8C,
    OBJECT_13 = 0x8D,
    OBJECT_14 = 0x8E,
    OBJECT_15 = 0x8F,
    ARRAY_0 = 0x90, // = [] length
    ARRAY_1 = 0x91,
    ARRAY_2 = 0x92,
    ARRAY_3 = 0x93,
    ARRAY_4 = 0x94,
    ARRAY_5 = 0x95,
    ARRAY_6 = 0x96,
    ARRAY_7 = 0x97,
    ARRAY_8 = 0x98,
    ARRAY_9 = 0x99,
    ARRAY_10 = 0x9A,
    ARRAY_11 = 0x9B,
    ARRAY_12 = 0x9C,
    ARRAY_13 = 0x9D,
    ARRAY_14 = 0x9E,
    ARRAY_15 = 0x9F,
    KEY_0 = 0xA0, // Index. Only used when stripping keys, uses string otherwise
    KEY_1 = 0xA1,
    KEY_2 = 0xA2,
    KEY_3 = 0xA3,
    KEY_4 = 0xA4,
    KEY_5 = 0xA5,
    KEY_6 = 0xA6,
    KEY_7 = 0xA7,
    KEY_8 = 0xA8,
    KEY_9 = 0xA9,
    KEY_10 = 0xAA,
    KEY_11 = 0xAB,
    KEY_12 = 0xAC,
    KEY_13 = 0xAD,
    KEY_14 = 0xAE,
    KEY_15 = 0xAF,
    STR_0 = 0xB0, // = Index of the string in the string section, unless in the string section.
    STR_1 = 0xB1,
    STR_2 = 0xB2,
    STR_3 = 0xB3,
    STR_4 = 0xB4,
    STR_5 = 0xB5,
    STR_6 = 0xB6,
    STR_7 = 0xB7,
    STR_8 = 0xB8,
    STR_9 = 0xB9,
    STR_10 = 0xBA,
    STR_11 = 0xBB,
    STR_12 = 0xBC,
    STR_13 = 0xBD,
    STR_14 = 0xBE,
    STR_15 = 0xBF,
    NULL = 0xC0,
    UNDEFINED = 0xC1,
    BOOL_FALSE = 0xC2,
    BOOL_TRUE = 0xC3,
    FINISHED = 0xC4, // Kill byte
    LIST_END = 0xC5, // special ext type
    UNUSED_C6 = 0xC6,
    OBJECT8 = 0xC7,
    OBJECT16 = 0xC8,
    OBJECT32 = 0xC9,
    FLOAT32 = 0xCA,
    FLOAT64 = 0xCB,
    UINT_8 = 0xCC,
    UINT_16 = 0xCD,
    UINT_32 = 0xCE,
    UINT_64 = 0xCF,
    INT_8 = 0xD0,
    INT_16 = 0xD1,
    INT_32 = 0xD2,
    INT_64 = 0xD3,
    KEY8 = 0xD4,
    KEY16 = 0xD5,
    KEY32 = 0xD6,
    STR8 = 0xD7,
    STR16 = 0xD8,
    STR32 = 0xD9,
    ARRAY8 = 0xDA,
    ARRAY16 = 0xDB,
    ARRAY32 = 0xDC,
    EXT8 = 0xDD,
    EXT16 = 0xDE,
    EXT32 = 0xDF,
    // 0xE0 - 0xFF negative fixint 
};

/**
 * Internal index for ext values.
 */
export enum JPExtType {
    // 0xD0 - 0xFF are reserve extend numbers
    Maps = 0xEE, // Size here is the array size of Map, not the buffer size
    Sets = 0xEF, // Size here is the array size of Set, not the buffer size
    Symbol = 0xF0, // Has fixed bool and string read after.
    RegEx = 0xF1, // Two strings
    BigUint64Array = 0xF2,
    BigInt64Array = 0xF3,
    Float64Array = 0xF4,
    Float32Array = 0xF5,
    Float16Array = 0xF6, // not in use yet
    Int32Array = 0xF7,
    Uint32Array = 0xF8,
    Uint16Array = 0xF9,
    Int16Array = 0xFA,
    Int8Array = 0xFB,
    Uint8Array = 0xFC,
    Uint8ClampedArray = 0xFD,
    Buffer = 0xFE,
    Date = 0xFF // MSGPACK Standard
};

/**
 * For creating a unique string list
 */
export class stringList {
    array: string[] = [];

    set = new Set();

    /**
     * For creating a unique string list
     * 
     * @param {string[]?} stringArray 
     */
    constructor(stringArray?: string[]) {
        if (stringArray) {
            this.array = stringArray;
            this.set = new Set(stringArray);
        }
        else {
            this.array = [];
            this.set = new Set();
        }
    };

    /**
     * Add string
     * 
     * @param {string} value 
     * @returns {number} index
     */
    add(value: string): number {
        if (!this.set.has(value)) {
            this.set.add(value);

            this.array.push(value);
        }

        return this.getIndex(value);
    };

    /**
     * Gets the string from the index
     * 
     * @param {number} value 
     * @returns {string}
     */
    get(value: number): string {
        return this.array[value];
    };

    /**
     * Shouldn't ever use!
     * 
     * @param {string} value 
     */
    remove(value: string) {
        if (this.set.has(value)) {
            this.set.delete(value);
            // Find the index of the value in the array and remove it
            const index = this.array.indexOf(value);

            if (index !== -1) {
                this.array.splice(index, 1);
            }
        }
    };

    /**
     * Gets the index for the string
     * 
     * @param {string} value 
     * @returns {number} index
     */
    getIndex(value: string): number {
        return this.array.indexOf(value);
    };

    /**
     * returns data as an array
     * 
     * @returns {string[]} string array
     */
    getValues(): string[] {
        return this.array;
    };

    /**
     * Check the set has the value
     * 
     * @param {string} value 
     * @returns {boolean} if the value is in the dataset
     */
    has(value: string): boolean {
        return this.set.has(value);
    };
};

/**
 * File flags
 */
export type JPFlags = {
    /**
     * For files over 4 gigs.
     * 
     * bit 0
     */
    LargeFile: bit,
    /**
     * Compressed file
     * 
     * bit 1
     */
    Compressed: bit,
    /**
     * CRC32 check
     * 
     * bit 2
     */
    Crc32: bit,
    /**
     * Encrypted
     * 
     * bit 3
     */
    Encrypted: bit,
    /**
     * Encryption value removed
     * 
     * bit 4
     */
    EncryptionExcluded: bit,
    /**
     * Keys removed (schema mode)
     * 
     * bit 5
     */
    KeyStripped: bit,
};

export type ContextOf<ContextType> = ContextType extends undefined
    ? object
    : {
        /**
         * Custom user-defined data, read/writable
         */
        context: ContextType;
    };

    /**
 * Options for `JPDecode`
 */
export type DecoderOptions<ContextType = undefined> = Readonly<
    Partial<{
        /**
         * Created from `ExtensionCodec` class.
         */
        extensionCodec: JPExtensionCodecType<ContextType>;

        context?: ContextType;

        /**
         * Object keys for when `stripKeys` was enabled during encoding.
         * 
         * This array MUST be passed to decoder for the file to be decoded.
         */
        keysArray?: string[];

        /**
         * 32 bit encryption key for when `stripEncryptKey` was enabled in encoding.
         * 
         * If the key was stripped from the file, this number MUST be passed to decoder for the file to be decoded.
         */
        encryptionKey?: number;

        /**
         * This ensures all 64 bit values return as `bigint`
         */
        enforceBigInt?: boolean;

        /**
         * Forces the decoder to only return only a valid JSON object.
         * 
         * This will mostly suppress / convert all extention types that aren't valid JSON.
         */
        makeJSON?: boolean;
    }>
> &
    ContextOf<ContextType>;

/**
 * Options for `JPEncode`
 */
export type EncoderOptions<ContextType = undefined> = Partial<
    Readonly<{
        extensionCodec?: JPExtensionCodecType<ContextType>;

        context?: ContextType;
        /**
         * Set the Endianness of the file.
         * 
         * Defaults to `little`.
         */
        endian?: endian;

        /**
         * If you want the file Buffer to be encrypted.
         * 
         * The key data to decrypt the file is kept within the file.
         * 
         * For extra security you can exclude this key from the file with `stripEncryptKey`.
         * 
         * If you do, you must save the `encryptionKey` object number after decoding or you won't be able to decrypt it later.
         * 
         * If you can also set your own 32 bit encryption key with `encryptionKey` in options here.
         * 
         * Note: It's highly recommended that you also use the `CRC32` to check the file after decryption to make sure the data is correct afterward.
         * 
         * Defaults to `false`.
         */
        encrypt?: boolean;

        /**
         * You can set your own 32 bit encryption key.
         * 
         * If you use `stripEncryptKey` you must save this value for later use. Can also be found in the `EncryptionKey` object after encoding.
         * 
         * Will be randomly assigned otherwise.
         */
        encryptionKey?: uint32;

        /**
         * Will remove the encryption key from the file.
         * 
         * You must save the `EncryptionKey` object number after decoding or you won't be able to decrypt the file later.
         * 
         * Defaults to `false`.
         */
        stripEncryptKey?: boolean;

        /**
         * Include a CRC32 hash check on the file. Hash is included in the file.
         * 
         * Hash can also be found in the `CRC32` object.
         * 
         * Defaults to `false`.
         */
        CRC32?: boolean;

        /**
         * Can futher decrease the file size with zlib.
         * 
         * Compression happens first before encrypted.
         * 
         * Defaults to `false`.
         */
        compress?: boolean;

        /**
         * For extra security you can strip all object keys from the data creating a "schema" like file.
         * 
         * You must save the `keysArray` object after encoding or you won't be able to decode the file later.
         * 
         * Defaults to `false`.
         */
        stripKeys?: boolean;

        /**
         * Byte amount to start and increase when a Buffer size is needed.
         * 
         * Larger amounts speed up writes.
         */
        growthIncrement?: number;
    }>
> &
    ContextOf<ContextType>;

export class JPBase {

    ////////////////
    //  BUFFERS   //
    ////////////////

    /**
     * Buffer for header data.
     */
    headerBuffer: Buffer | null = null;

    ////////////////
    //  WRITERS   //
    ////////////////

    useFile = false;

    valueWriter: BiWriter<any, any> | null = null;

    strWriter: BiWriter<any, any> | null = null;

    compWriter: BiWriter<any, any> | null = null;

    ////////////////
    //  READERS   //
    ////////////////

    fileReader: BiReader<any, any> | null = null;

    valueReader: BiReader<any, any> | null = null;

    strReader: BiReader<any, any> | null = null;

    compReader: BiReader<any, any> | null = null;

    ////////////////
    //   SIZES    //
    ////////////////

    /**
     * Buffer size. 16mbs
     */
    growthIncrement = GROWTHINCREMENT_DEFAULT;

    /**
     * Internal size.
     */
    private _HEADER_SIZE: ubyte = 0;

    /**
     * Size of the header buffer.
     */
    set HEADER_SIZE(value: uint8) {
        this._HEADER_SIZE = value;
    };

    /**
     * Size of the header buffer.
     */
    get HEADER_SIZE(): uint8 {
        if (this._HEADER_SIZE != 0) {
            return this._HEADER_SIZE;
        } else if (this.headerBuffer != null) {
            this._HEADER_SIZE = this.headerBuffer.length;

            return this.headerBuffer.length;
        } else {
            let HEADER_SIZE = 32;

            if (this.Crc32) {
                HEADER_SIZE += 4;
            }

            if (this.Encrypted && !this.EncryptionExcluded) {
                HEADER_SIZE += 4;
            }

            this._HEADER_SIZE = HEADER_SIZE;

            return this._HEADER_SIZE;
        }
    };

    /**
     * Internal size.
     */
    private _VALUE_SIZE: uint64 = 0n;

    /**
     * The size of the section that has values data.
     */
    set VALUE_SIZE(value: BigValue) {
        this._VALUE_SIZE = BigInt(value);
    };

    /**
      * The size of the section that has every other type of data.
      */
    get VALUE_SIZE(): uint64 {
        if (this._VALUE_SIZE != 0n) {
            return this._VALUE_SIZE;
        } else if (this.valueWriter != null) {
            this._VALUE_SIZE = BigInt(this.valueWriter.offset);
            return this._VALUE_SIZE;
        } else {
            return 0n;
        }
    };

    /**
     * Internal size.
     */
    private _STR_SIZE: uint64 = 0n;

    /**
     * The size of the section that has string / key data.
     */
    set STR_SIZE(value: BigValue) {
        this._STR_SIZE = BigInt(value);
    };

    /**
     * The size of the section that has string / key data.
     */
    get STR_SIZE(): uint64 {
        if (this._STR_SIZE != 0n) {
            return this._STR_SIZE;
        } else if (this.strWriter != null) {
            this._STR_SIZE = BigInt(this.strWriter.offset);
            return this._STR_SIZE;
        } else {
            return 0n;
        }
    };

    /**
     * Internal size.
     */
    private _DATA_SIZE: uint64 = 0n;

    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    set DATA_SIZE(value: BigValue) {
        this._DATA_SIZE = BigInt(value);
    };

    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    get DATA_SIZE(): uint64 {
        if (this._DATA_SIZE != 0n) {
            return this._DATA_SIZE;
        } else if (this._VALUE_SIZE != 0n && this._STR_SIZE != 0n) {
            this._DATA_SIZE = BigInt(this._VALUE_SIZE + this._STR_SIZE);
            return this._DATA_SIZE;
        } else if (this.strWriter != null && this.valueWriter != null) {
            this._DATA_SIZE = BigInt(this.valueWriter.size + this.strWriter.length);
            return this._DATA_SIZE;
        } else {
            return 0n;
        }
    };

    ////////////////
    //   FLAGS    //
    ////////////////

    /**
    * Flags for file header.
    */
    flags: JPFlags = {
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
    set LargeFile(bit: bit) {
        this.flags.LargeFile = (bit & 1) as bit;
    };

    /**
     * For files over 4 gigs.
     * 
     * @returns {bit} flag
     */
    get LargeFile(): bit {
        return this.flags.LargeFile;
    };

    /**
     * If the data is zlib compressed.
     * 
     * @returns {bit} flag
     */
    get Compressed(): bit {
        return this.flags.Compressed;
    };

    /**
     * If the data is zlib compressed.
     * 
     * @param {bit} bit flag
     */
    set Compressed(bit: bit) {
        this.flags.Compressed = (bit & 1) as bit;
    };

    /**
     * If a CRC32 is done on the data.
     * 
     * @returns {bit} flag
     */
    get Crc32(): bit {
        return this.flags.Crc32;
    };

    /**
     * If a CRC32 is done on the data.
     * 
     * @param {bit} bit flag
     */
    set Crc32(bit: bit) {
        this.flags.Crc32 = (bit & 1) as bit;
    };

    /**
     * If the file is encrypted.
     * 
     * @returns {bit} flag
     */
    get Encrypted(): bit {
        return this.flags.Encrypted;
    };

    /**
     * If the file is encrypted.
     * 
     * @param {bit} bit flag
     */
    set Encrypted(bit: bit) {
        this.flags.Encrypted = (bit & 1) as bit;
    };

    /**
     * If the file's encryption key is not kept within the file.
     * 
     * @returns {bit} flag
     */
    get EncryptionExcluded(): bit {
        return this.flags.EncryptionExcluded;
    };

    /**
     * If the file's encryption key is not kept within the file.
     * 
     * @param {bit} bit flag
     */
    set EncryptionExcluded(bit: bit) {
        this.flags.EncryptionExcluded = (bit & 1) as bit;
    };

    /**
     * If the object keys are removed from the file.
     * 
     * @returns {bit} flag
     */
    get KeyStripped(): bit {
        return this.flags.KeyStripped;
    };

    /**
     * If the object keys are removed from the file.
     * 
     * @param {bit} bit flag
     */
    set KeyStripped(bit: bit) {
        this.flags.KeyStripped = (bit & 1) as bit;
    };

    ////////////////////
    // EXTRA HEADERS  //
    ////////////////////

    /**
     * Encryption key For decryption.
     */
    private _encryptionKey: uint32 = 0;

    /**
     * Encryption value. For decryption.
     */
    set encryptionKey(value: uint32) {
        this._encryptionKey = value >>> 0;
    }

    /**
     * Encryption value. For decryption.
     */
    get encryptionKey() {
        return this._encryptionKey;
    }

    /**
     * Check hash value.
     */
    private _CRC32: uint32 = 0;

    /**
     * Check hash value.
     */
    set CRC32(value: number) {
        this._CRC32 = value;
    }

    /**
     * Check hash value.
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
    keysArray: string[] = [];

    entered = false;

    fileName = "";

    errored = false;

    errorMessage = "";

    throwError(errorMessage: string) {
        this.errored = true;

        this.errorMessage += errorMessage;

        throw new Error(this.errorMessage);
    };

    addError(errorMessage: string) {
        this.errored = true;
        
        this.errorMessage += errorMessage;

        console.warn(this.errorMessage);
    };
};

export class JPBaseAsync {

    ////////////////
    //  BUFFERS   //
    ////////////////

    /**
     * Buffer for header data.
     */
    headerBuffer: Buffer | null = null;

    ////////////////
    //  WRITERS   //
    ////////////////

    useFile = false;

    valueWriterAsync: BiWriterAsync<any, any> | null = null;

    strWriterAsync: BiWriterAsync<any, any> | null = null;

    compWriterAsync: BiWriterAsync<any, any> | null = null;

    ////////////////
    //  READERS   //
    ////////////////

    fileReaderAsync: BiReaderAsync<any, any> | null = null;

    valueReaderAsync: BiReaderAsync<any, any> | null = null;

    strReaderAsync: BiReaderAsync<any, any> | null = null;

    compReaderAsync: BiReaderAsync<any, any> | null = null;

    ////////////////
    //   SIZES    //
    ////////////////

    /**
     * Buffer size. 16mbs
     */
    growthIncrement = GROWTHINCREMENT_DEFAULT;

    /**
     * Internal size.
     */
    private _HEADER_SIZE: ubyte = 0;

    /**
     * Size of the header buffer.
     */
    set HEADER_SIZE(value: uint8) {
        this._HEADER_SIZE = value;
    };

    /**
     * Size of the header buffer.
     */
    get HEADER_SIZE(): uint8 {
        if (this._HEADER_SIZE != 0) {
            return this._HEADER_SIZE;
        } else if (this.headerBuffer != null) {
            this._HEADER_SIZE = this.headerBuffer.length;

            return this.headerBuffer.length;
        } else {
            let HEADER_SIZE = 32;

            if (this.Crc32) {
                HEADER_SIZE += 4;
            }

            if (this.Encrypted && !this.EncryptionExcluded) {
                HEADER_SIZE += 4;
            }

            this._HEADER_SIZE = HEADER_SIZE;

            return this._HEADER_SIZE;
        }
    };

    /**
     * Internal size.
     */
    private _VALUE_SIZE: uint64 = 0n;

    /**
     * The size of the section that has values data.
     */
    set VALUE_SIZE(value: BigValue) {
        this._VALUE_SIZE = BigInt(value);
    };

    /**
      * The size of the section that has every other type of data.
      */
    get VALUE_SIZE(): uint64 {
        if (this._VALUE_SIZE != 0n) {
            return this._VALUE_SIZE;
        } else if (this.valueWriterAsync != null) {
            this._VALUE_SIZE = BigInt(this.valueWriterAsync.offset);
            return this._VALUE_SIZE;
        } else {
            return 0n;
        }
    };

    /**
     * Internal size.
     */
    private _STR_SIZE: uint64 = 0n;

    /**
     * The size of the section that has string / key data.
     */
    set STR_SIZE(value: BigValue) {
        this._STR_SIZE = BigInt(value);
    };

    /**
     * The size of the section that has string / key data.
     */
    get STR_SIZE(): uint64 {
        if (this._STR_SIZE != 0n) {
            return this._STR_SIZE;
        } else if (this.strWriterAsync != null) {
            this._STR_SIZE = BigInt(this.strWriterAsync.offset);
            return this._STR_SIZE;
        } else {
            return 0n;
        }
    };

    /**
     * Internal size.
     */
    private _DATA_SIZE: uint64 = 0n;

    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    set DATA_SIZE(value: BigValue) {
        this._DATA_SIZE = BigInt(value);
    };

    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    get DATA_SIZE(): uint64 {
        if (this._DATA_SIZE != 0n) {
            return this._DATA_SIZE;
        } else if (this._VALUE_SIZE != 0n && this._STR_SIZE != 0n) {
            this._DATA_SIZE = BigInt(this._VALUE_SIZE + this._STR_SIZE);
            return this._DATA_SIZE;
        } else if (this.strWriterAsync != null && this.valueWriterAsync != null) {
            this._DATA_SIZE = BigInt(this.valueWriterAsync.size + this.strWriterAsync.length);
            return this._DATA_SIZE;
        } else {
            return 0n;
        }
    };

    ////////////////
    //   FLAGS    //
    ////////////////

    /**
    * Flags for file header.
    */
    flags: JPFlags = {
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
    set LargeFile(bit: bit) {
        this.flags.LargeFile = (bit & 1) as bit;
    };

    /**
     * For files over 4 gigs.
     * 
     * @returns {bit} flag
     */
    get LargeFile(): bit {
        return this.flags.LargeFile;
    };

    /**
     * If the data is zlib compressed.
     * 
     * @returns {bit} flag
     */
    get Compressed(): bit {
        return this.flags.Compressed;
    };

    /**
     * If the data is zlib compressed.
     * 
     * @param {bit} bit flag
     */
    set Compressed(bit: bit) {
        this.flags.Compressed = (bit & 1) as bit;
    };

    /**
     * If a CRC32 is done on the data.
     * 
     * @returns {bit} flag
     */
    get Crc32(): bit {
        return this.flags.Crc32;
    };

    /**
     * If a CRC32 is done on the data.
     * 
     * @param {bit} bit flag
     */
    set Crc32(bit: bit) {
        this.flags.Crc32 = (bit & 1) as bit;
    };

    /**
     * If the file is encrypted.
     * 
     * @returns {bit} flag
     */
    get Encrypted(): bit {
        return this.flags.Encrypted;
    };

    /**
     * If the file is encrypted.
     * 
     * @param {bit} bit flag
     */
    set Encrypted(bit: bit) {
        this.flags.Encrypted = (bit & 1) as bit;
    };

    /**
     * If the file's encryption key is not kept within the file.
     * 
     * @returns {bit} flag
     */
    get EncryptionExcluded(): bit {
        return this.flags.EncryptionExcluded;
    };

    /**
     * If the file's encryption key is not kept within the file.
     * 
     * @param {bit} bit flag
     */
    set EncryptionExcluded(bit: bit) {
        this.flags.EncryptionExcluded = (bit & 1) as bit;
    };

    /**
     * If the object keys are removed from the file.
     * 
     * @returns {bit} flag
     */
    get KeyStripped(): bit {
        return this.flags.KeyStripped;
    };

    /**
     * If the object keys are removed from the file.
     * 
     * @param {bit} bit flag
     */
    set KeyStripped(bit: bit) {
        this.flags.KeyStripped = (bit & 1) as bit;
    };

    ////////////////////
    // EXTRA HEADERS  //
    ////////////////////

    /**
     * Encryption key For decryption.
     */
    private _encryptionKey: uint32 = 0;

    /**
     * Encryption value. For decryption.
     */
    set encryptionKey(value: uint32) {
        this._encryptionKey = value >>> 0;
    }

    /**
     * Encryption value. For decryption.
     */
    get encryptionKey() {
        return this._encryptionKey;
    }

    /**
     * Check hash value.
     */
    private _CRC32: uint32 = 0;

    /**
     * Check hash value.
     */
    set CRC32(value: number) {
        this._CRC32 = value;
    }

    /**
     * Check hash value.
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
    keysArray: string[] = [];

    entered = false;

    fileName = "";

    errored = false;

    errorMessage = "";

    throwError(errorMessage: string) {
        this.errored = true;

        this.errorMessage += errorMessage;

        throw new Error(this.errorMessage);
    };

    addError(errorMessage: string) {
        this.errored = true;

        this.errorMessage += errorMessage;

        console.warn(this.errorMessage);
    };
};