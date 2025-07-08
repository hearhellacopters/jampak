import fs from "fs";
import zlib from 'zlib';
import { constants as bufferConstants } from "node:buffer";
import {
    BiReader,
    BiWriter,
    BiReaderStream,
    BiWriterStream,
} from 'bireader';
import pack from '../package.json';

type reader = BiReader | BiReaderStream | BiWriter | BiWriterStream;

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
 * Compress a file using Deflate, framed with [length][chunk] blocks.
 */
export function deflateFileSync(inWriter: BiWriterStream, outWriter: BiWriterStream): void {
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
};

/**
 * Decompress a framed deflate-compressed file.
 */
export function inflateFileSync(inReader: BiReaderStream, outWriter: BiWriterStream): void {
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
};

/**
 * Compress a Buffer using Deflate, framed with [length][chunk] blocks.
 */
export function deflateBuffer(inWriter: reader): Buffer {
    let bytesToProcess = inWriter.size;

    let bytesStart = 0;

    let bytesRead = 0;

    const buffers:Buffer[] = [];

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
};

/**
 * Decompress a framed deflate-compressed buffer.
 */
export function inflateBuffer(bw: reader): Buffer {
    const startingOff = bw.offset;

    const size = bw.size;
    
    const totalBuffer = size - startingOff;
    
    let bytesRead = 0;

    const buffers:Buffer[] = [];

    while (bytesRead < totalBuffer) {
        const chunkLen = bw.readUInt32LE(); bytesRead += 4;
    
        const compressed = bw.extract(chunkLen); bytesRead += chunkLen;
        
        const decompressed = zlib.inflateSync(compressed);

        buffers.push(decompressed);
    }

    return Buffer.concat(buffers);
};

export function copyfile(inputPath: string, start: number, outputPath: string) {
    const chunkSize = 64 * 1024;

    const buffer = Buffer.alloc(chunkSize);
    
    const fd1 = fs.openSync(inputPath, "r");

    const fd2 = fs.openSync(outputPath, "w+");

    const stat = fs.fstatSync(fd1);

    var size = stat.size;

    let remaining = size - start;
    
    let readPos = start;

    let writePos = 0;

    while (remaining > 0) {
        const actualRead = Math.min(chunkSize, remaining);

        if (actualRead == 0) break;

        fs.readSync(fd1, buffer, 0, actualRead, readPos);

        fs.writeSync(fd2, buffer, 0, actualRead, writePos);

        writePos += actualRead;

        readPos += actualRead;

        remaining -= actualRead;
    }

    fs.closeSync(fd1);
    
    fs.closeSync(fd2);
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

/**
 * Merges 2 or 3 files into 1.
 * 
 * @param {string} inputFile1 - file path
 * @param {string} inputFile2 - file path
 * @param {string} outputFile - file path
 * @param {string?} inputFile3 - file path
 */
export function concatenateFilesSync(inputFile1:string, inputFile2:string, outputFile:string, inputFile3?:string,) {
    const bufferSize = 0x4000; // 16384 bytes

    const fdIn1 = fs.openSync(inputFile1, 'r');
    const fdIn2 = fs.openSync(inputFile2, 'r');
    var fdIn3:number|undefined;
    if(inputFile3 != undefined){
        fdIn3 = fs.openSync(inputFile3, 'r');
    }
    const fdOut = fs.openSync(outputFile, 'w');

    try {
        const buffer = Buffer.alloc(bufferSize);
        let bytesRead:number;

        while ((bytesRead = fs.readSync(fdIn1, buffer, 0, bufferSize, null)) > 0) {
            fs.writeSync(fdOut, buffer, 0, bytesRead);
        }

        while ((bytesRead = fs.readSync(fdIn2, buffer, 0, bufferSize, null)) > 0) {
            fs.writeSync(fdOut, buffer, 0, bytesRead);
        }

        if(fdIn3 != undefined){
            while ((bytesRead = fs.readSync(fdIn3, buffer, 0, bufferSize, null)) > 0) {
                fs.writeSync(fdOut, buffer, 0, bytesRead);
            }
        }
    } finally {
        // Close all file descriptors
        fs.closeSync(fdIn1);
        fs.closeSync(fdIn2);
        if(fdIn3 != undefined){
            fs.closeSync(fdIn3);
        }
        fs.closeSync(fdOut);

        // then delete the others
        fs.unlinkSync(inputFile1);
        fs.unlinkSync(inputFile2);
        if(inputFile3 != undefined){
            fs.unlinkSync(inputFile3);
        }
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
    OBJECT_0   = 0x80, // = {} length
    OBJECT_1   = 0x81,
    OBJECT_2   = 0x82,
    OBJECT_3   = 0x83,
    OBJECT_4   = 0x84,
    OBJECT_5   = 0x85,
    OBJECT_6   = 0x86,
    OBJECT_7   = 0x87,
    OBJECT_8   = 0x88,
    OBJECT_9   = 0x89,
    OBJECT_10  = 0x8A,
    OBJECT_11  = 0x8B,
    OBJECT_12  = 0x8C,
    OBJECT_13  = 0x8D,
    OBJECT_14  = 0x8E,
    OBJECT_15  = 0x8F,
    ARRAY_0    = 0x90, // = [] length
    ARRAY_1    = 0x91,
    ARRAY_2    = 0x92,
    ARRAY_3    = 0x93,
    ARRAY_4    = 0x94,
    ARRAY_5    = 0x95,
    ARRAY_6    = 0x96,
    ARRAY_7    = 0x97,
    ARRAY_8    = 0x98,
    ARRAY_9    = 0x99,
    ARRAY_10   = 0x9A,
    ARRAY_11   = 0x9B,
    ARRAY_12   = 0x9C,
    ARRAY_13   = 0x9D,
    ARRAY_14   = 0x9E,
    ARRAY_15   = 0x9F,
    KEY_0      = 0xA0, // Index. Only used when stripping keys, uses string otherwise
    KEY_1      = 0xA1,
    KEY_2      = 0xA2,
    KEY_3      = 0xA3,
    KEY_4      = 0xA4,
    KEY_5      = 0xA5,
    KEY_6      = 0xA6,
    KEY_7      = 0xA7,
    KEY_8      = 0xA8,
    KEY_9      = 0xA9,
    KEY_10     = 0xAA,
    KEY_11     = 0xAB,
    KEY_12     = 0xAC,
    KEY_13     = 0xAD,
    KEY_14     = 0xAE,
    KEY_15     = 0xAF,
    STR_0      = 0xB0, // = Index of the string in the string section, unless in the string section.
    STR_1      = 0xB1,
    STR_2      = 0xB2,
    STR_3      = 0xB3,
    STR_4      = 0xB4,
    STR_5      = 0xB5,
    STR_6      = 0xB6,
    STR_7      = 0xB7,
    STR_8      = 0xB8,
    STR_9      = 0xB9,
    STR_10     = 0xBA,
    STR_11     = 0xBB,
    STR_12     = 0xBC,
    STR_13     = 0xBD,
    STR_14     = 0xBE,
    STR_15     = 0xBF,
    NULL       = 0xC0, 
    UNDEFINED  = 0xC1, 
    BOOL_FALSE = 0xC2, 
    BOOL_TRUE  = 0xC3, 
    FINISHED   = 0xC4, // Kill byte
    LIST_END   = 0xC5, // special ext type
    UNUSED_C6  = 0xC6,
    OBJECT8    = 0xC7,
    OBJECT16   = 0xC8,
    OBJECT32   = 0xC9,
    FLOAT32    = 0xCA,
    FLOAT64    = 0xCB,
    UINT_8     = 0xCC,
    UINT_16    = 0xCD,
    UINT_32    = 0xCE,
    UINT_64    = 0xCF,
    INT_8      = 0xD0,
    INT_16     = 0xD1,
    INT_32     = 0xD2,
    INT_64     = 0xD3,
    KEY8       = 0xD4,
    KEY16      = 0xD5,
    KEY32      = 0xD6,
    STR8       = 0xD7,
    STR16      = 0xD8,
    STR32      = 0xD9,
    ARRAY8     = 0xDA,
    ARRAY16    = 0xDB,
    ARRAY32    = 0xDC,
    EXT8       = 0xDD,
    EXT16      = 0xDE,
    EXT32      = 0xDF,
              // 0xE0 - 0xFF negative fixint 
};

/**
 * Internal index for ext values.
 */
export enum JPExtType {
                     // 0xD0 - 0xFF are reserve extend numbers
    Maps              = 0xEE, // Size here is the array size of Map, not the buffer size
    Sets              = 0xEF, // Size here is the array size of Set, not the buffer size
    Symbol            = 0xF0, // Has fixed bool and string read after.
    RegEx             = 0xF1, // Two strings
    BigUint64Array    = 0xF2, 
    BigInt64Array     = 0xF3,
    Float64Array      = 0xF4,
    Float32Array      = 0xF5,
    Float16Array      = 0xF6, // not in use yet
    Int32Array        = 0xF7,
    Uint32Array       = 0xF8,
    Uint16Array       = 0xF9,
    Int16Array        = 0xFA,
    Int8Array         = 0xFB,
    Uint8Array        = 0xFC,
    Uint8ClampedArray = 0xFD,
    Buffer            = 0xFE,
    Date              = 0xFF // MSGPACK Standard
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

    useStream = false;

    valueWriter: BiWriter | BiWriterStream | null = null;

    strWriter:   BiWriter | BiWriterStream | null = null;

    compWriter:  BiWriter | BiWriterStream | null = null;

    ////////////////
    //  READERS   //
    ////////////////

    fileReader:  BiReader | BiReaderStream | null = null;

    valueReader: BiReader | BiReaderStream | null = null;

    strReader:   BiReader | BiReaderStream | null = null;    

    compReader:  BiReader | BiReaderStream | null = null;

    ////////////////
    //   SIZES    //
    ////////////////

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
            this.valueWriter.get;
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
            this.strWriter.get;
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
    get Compressed():bit {
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
     * Check hash value. From value data on after decomp and decryption.
     */
    private _CRC32: uint32 = 0;

    /**
     * Check hash value. From value data on after decomp and decryption.
     */
    set CRC32(value:number){
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
    keysArray: string[] = [];

    entered = false;

    fileName = "";
};