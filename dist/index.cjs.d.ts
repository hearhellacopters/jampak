import { BiWriter, BiWriterStream, BiReader, BiReaderStream } from 'bireader';

type endian = "little" | "big";
type BigValue = bigint | number;
/**
 * Between 0 and 1.
 */
type bit = 1 | 0;
/**
 * Between 0 and 255.
 */
type ubyte = number;
/**
 * Between 0 and 255.
 */
type uint8 = number;
/**
 * Between 0 to 65535.
 */
type uint16 = number;
/**
 * Between 0 to 4294967295.
 */
type uint32 = number;
/**
 * Between 0  to 18446744073709551615
 */
type uint64 = bigint;
/**
 * Internal index for values.
 */
declare enum JPType {
    OBJECT_0 = 128,// = {} length
    OBJECT_1 = 129,
    OBJECT_2 = 130,
    OBJECT_3 = 131,
    OBJECT_4 = 132,
    OBJECT_5 = 133,
    OBJECT_6 = 134,
    OBJECT_7 = 135,
    OBJECT_8 = 136,
    OBJECT_9 = 137,
    OBJECT_10 = 138,
    OBJECT_11 = 139,
    OBJECT_12 = 140,
    OBJECT_13 = 141,
    OBJECT_14 = 142,
    OBJECT_15 = 143,
    ARRAY_0 = 144,// = [] length
    ARRAY_1 = 145,
    ARRAY_2 = 146,
    ARRAY_3 = 147,
    ARRAY_4 = 148,
    ARRAY_5 = 149,
    ARRAY_6 = 150,
    ARRAY_7 = 151,
    ARRAY_8 = 152,
    ARRAY_9 = 153,
    ARRAY_10 = 154,
    ARRAY_11 = 155,
    ARRAY_12 = 156,
    ARRAY_13 = 157,
    ARRAY_14 = 158,
    ARRAY_15 = 159,
    KEY_0 = 160,// Index. Only used when stripping keys, uses string otherwise
    KEY_1 = 161,
    KEY_2 = 162,
    KEY_3 = 163,
    KEY_4 = 164,
    KEY_5 = 165,
    KEY_6 = 166,
    KEY_7 = 167,
    KEY_8 = 168,
    KEY_9 = 169,
    KEY_10 = 170,
    KEY_11 = 171,
    KEY_12 = 172,
    KEY_13 = 173,
    KEY_14 = 174,
    KEY_15 = 175,
    STR_0 = 176,// = Index of the string in the string section, unless in the string section.
    STR_1 = 177,
    STR_2 = 178,
    STR_3 = 179,
    STR_4 = 180,
    STR_5 = 181,
    STR_6 = 182,
    STR_7 = 183,
    STR_8 = 184,
    STR_9 = 185,
    STR_10 = 186,
    STR_11 = 187,
    STR_12 = 188,
    STR_13 = 189,
    STR_14 = 190,
    STR_15 = 191,
    NULL = 192,
    UNDEFINED = 193,
    BOOL_FALSE = 194,
    BOOL_TRUE = 195,
    FINISHED = 196,// Kill byte
    LIST_END = 197,// special ext type
    UNUSED_C6 = 198,
    OBJECT8 = 199,
    OBJECT16 = 200,
    OBJECT32 = 201,
    FLOAT32 = 202,
    FLOAT64 = 203,
    UINT_8 = 204,
    UINT_16 = 205,
    UINT_32 = 206,
    UINT_64 = 207,
    INT_8 = 208,
    INT_16 = 209,
    INT_32 = 210,
    INT_64 = 211,
    KEY8 = 212,
    KEY16 = 213,
    KEY32 = 214,
    STR8 = 215,
    STR16 = 216,
    STR32 = 217,
    ARRAY8 = 218,
    ARRAY16 = 219,
    ARRAY32 = 220,
    EXT8 = 221,
    EXT16 = 222,
    EXT32 = 223
}
/**
 * Internal index for ext values.
 */
declare enum JPExtType {
    Maps = 238,// Size here is the array size of Map, not the buffer size
    Sets = 239,// Size here is the array size of Set, not the buffer size
    Symbol = 240,// Has fixed bool and string read after.
    RegEx = 241,// Two strings
    BigUint64Array = 242,
    BigInt64Array = 243,
    Float64Array = 244,
    Float32Array = 245,
    Float16Array = 246,// not in use yet
    Int32Array = 247,
    Uint32Array = 248,
    Uint16Array = 249,
    Int16Array = 250,
    Int8Array = 251,
    Uint8Array = 252,
    Uint8ClampedArray = 253,
    Buffer = 254,
    Date = 255
}
/**
 * File flags
 */
type JPFlags = {
    /**
     * For files over 4 gigs.
     *
     * bit 0
     */
    LargeFile: bit;
    /**
     * Compressed file
     *
     * bit 1
     */
    Compressed: bit;
    /**
     * CRC32 check
     *
     * bit 2
     */
    Crc32: bit;
    /**
     * Encrypted
     *
     * bit 3
     */
    Encrypted: bit;
    /**
     * Encryption value removed
     *
     * bit 4
     */
    EncryptionExcluded: bit;
    /**
     * Keys removed (schema mode)
     *
     * bit 5
     */
    KeyStripped: bit;
};
type ContextOf<ContextType> = ContextType extends undefined ? object : {
    /**
     * Custom user-defined data, read/writable
     */
    context: ContextType;
};
declare class JPBase {
    /**
     * Buffer for header data.
     */
    headerBuffer: Buffer | null;
    useStream: boolean;
    valueWriter: BiWriter | BiWriterStream | null;
    strWriter: BiWriter | BiWriterStream | null;
    compWriter: BiWriter | BiWriterStream | null;
    fileReader: BiReader | BiReaderStream | null;
    valueReader: BiReader | BiReaderStream | null;
    strReader: BiReader | BiReaderStream | null;
    compReader: BiReader | BiReaderStream | null;
    /**
     * Internal size.
     */
    private _HEADER_SIZE;
    /**
     * Size of the header buffer.
     */
    set HEADER_SIZE(value: uint8);
    /**
     * Size of the header buffer.
     */
    get HEADER_SIZE(): uint8;
    /**
     * Internal size.
     */
    private _VALUE_SIZE;
    /**
     * The size of the section that has values data.
     */
    set VALUE_SIZE(value: BigValue);
    /**
      * The size of the section that has every other type of data.
      */
    get VALUE_SIZE(): uint64;
    /**
     * Internal size.
     */
    private _STR_SIZE;
    /**
     * The size of the section that has string / key data.
     */
    set STR_SIZE(value: BigValue);
    /**
     * The size of the section that has string / key data.
     */
    get STR_SIZE(): uint64;
    /**
     * Internal size.
     */
    private _DATA_SIZE;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    set DATA_SIZE(value: BigValue);
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    get DATA_SIZE(): uint64;
    /**
    * Flags for file header.
    */
    flags: JPFlags;
    /**
     * For files over 4 gigs.
     *
     * @param {bit} bit flag
     */
    set LargeFile(bit: bit);
    /**
     * For files over 4 gigs.
     *
     * @returns {bit} flag
     */
    get LargeFile(): bit;
    /**
     * If the data is zlib compressed.
     *
     * @returns {bit} flag
     */
    get Compressed(): bit;
    /**
     * If the data is zlib compressed.
     *
     * @param {bit} bit flag
     */
    set Compressed(bit: bit);
    /**
     * If a CRC32 is done on the data.
     *
     * @returns {bit} flag
     */
    get Crc32(): bit;
    /**
     * If a CRC32 is done on the data.
     *
     * @param {bit} bit flag
     */
    set Crc32(bit: bit);
    /**
     * If the file is encrypted.
     *
     * @returns {bit} flag
     */
    get Encrypted(): bit;
    /**
     * If the file is encrypted.
     *
     * @param {bit} bit flag
     */
    set Encrypted(bit: bit);
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @returns {bit} flag
     */
    get EncryptionExcluded(): bit;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @param {bit} bit flag
     */
    set EncryptionExcluded(bit: bit);
    /**
     * If the object keys are removed from the file.
     *
     * @returns {bit} flag
     */
    get KeyStripped(): bit;
    /**
     * If the object keys are removed from the file.
     *
     * @param {bit} bit flag
     */
    set KeyStripped(bit: bit);
    /**
     * Encryption key For decryption.
     */
    private _encryptionKey;
    /**
     * Encryption value. For decryption.
     */
    set encryptionKey(value: uint32);
    /**
     * Encryption value. For decryption.
     */
    get encryptionKey(): uint32;
    /**
     * Check hash value.
     */
    private _CRC32;
    /**
     * Check hash value.
     */
    set CRC32(value: number);
    /**
     * Check hash value.
     */
    get CRC32(): number;
    /**
     * Object keys for when `stripKeys` was enabled in encoding.
     *
     * This array MUST be passed to decoder for the file to be decoded.
     */
    keysArray: string[];
    entered: boolean;
    fileName: string;
    errored: boolean;
    errorMessage: string;
    throwError(errorMessage: string): void;
    addError(errorMessage: string): void;
}

/**
 * Options for `JPEncode`
 */
type EncoderOptions<ContextType = undefined> = Partial<Readonly<{
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
}>> & ContextOf<ContextType>;
/**
 * Create with `EncoderOptions`
 */
declare class JPEncode<ContextType = undefined> extends JPBase {
    private readonly extensionCodec;
    private readonly context;
    private stringList;
    private keyList;
    private depth;
    /**
     * JP or PJ
     */
    MAGIC: uint16;
    /**
     * Endianness. Defaults to ``little``
     */
    endian: endian;
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MAJOR(): ubyte;
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MINOR(): ubyte;
    CRC32Hash: number;
    /**
     * Set up with basic options
     *
     * @param {EncoderOptions?} encodeOptions - options for encoding
     */
    constructor(encodeOptions?: EncoderOptions<ContextType>);
    private clone;
    /**
     * Basic encode, will run options that were set in constructor.
     *
     * @param {any} object - Data to encode
     * @param {string} filePath - Optional file path to write the file to directly
     * @returns {Buffer}
     */
    encode(object: unknown, filePath?: string): Buffer;
    private reinitializeState;
    private doEncode;
    /**
     * Writes an `Object` to the buffer as `Record<string, unknown>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeObject(valueWriter: BiWriter | BiWriterStream, object: Record<string, unknown>, depth?: number): number;
    /**
     * Writes an `Array` to the buffer as `Array<unknown>`
     *
     * @param valueWriter - Writer
     * @param array - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeArray(valueWriter: BiWriter | BiWriterStream, array: Array<unknown>, depth?: number): number;
    /**
     * Writes a `string` to the buffer's string section.
     *
     * @param valueWriter - Writer
     * @param string - Data to encode
     * @param isKey If the string is used a an Object key. Only used when `stripKeys` is enabled.
     * @returns The `number` of bytes written
     */
    encodeString(valueWriter: BiWriter | BiWriterStream, string: string, isKey?: boolean): number;
    /**
     * Writes a `null` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeNull(valueWriter: BiWriter | BiWriterStream): number;
    /**
     * Writes an `undefined` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeUndefined(valueWriter: BiWriter | BiWriterStream): number;
    /**
     * Writes a `boolean` true or false to the buffer
     *
     * @param valueWriter - Writer
     * @param object - `true` or `false`
     * @returns The `number` of bytes written
     */
    encodeBoolean(valueWriter: BiWriter | BiWriterStream, object: boolean): number;
    /**
     * Writes an "finished" byte to the buffer. End the loop when hit if not finished otherwise.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeFinished(valueWriter: BiWriter | BiWriterStream): number;
    /**
     * Writes a "list end" byte to the buffer, useful when pulling loose data and don't want to break the whole loop.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeListEnd(valueWriter: BiWriter | BiWriterStream): number;
    /**
     * Writes a `number` to the buffer . Computes the right byte size base on value.
     *
     * Notes: Use `encodeBigInt64` for `bigint` types.
     *
     * @param valueWriter - Writer
     * @param number - Data to encode
     * @returns The `number` of bytes written
     */
    encodeNumber(valueWriter: BiWriter | BiWriterStream, number: number): number;
    /**
     * Writes a `bigint` to the buffer. Always written as a 64 bit value.
     *
     * @param valueWriter - Writer
     * @param bigint - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBigInt64(valueWriter: BiWriter | BiWriterStream, bigint: bigint): number;
    private encodeStringHeader;
    private writeString;
    private writeStringsData;
    private encodeNumberAsFloat;
    private encodeExtension;
    /**
     * Writes a `Map` to the buffer as `Map<key, value>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeMap<K, V>(valueWriter: BiWriter | BiWriterStream, object: Map<K, V>, depth?: number): number;
    /**
     * Writes a `Set` to the buffer as `Set<type>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeSet<T>(valueWriter: BiWriter | BiWriterStream, object: Set<T>, depth?: number): number;
    /**
     * Writes a `symbol` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeSymbol(valueWriter: BiWriter | BiWriterStream, object: symbol): number;
    /**
     * Writes a `RegEx` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeRegEx(valueWriter: BiWriter | BiWriterStream, object: RegExp): number;
    /**
     * Writes a `TypedArray` or `Buffer` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBinary(valueWriter: BiWriter | BiWriterStream, object: Buffer | ArrayBufferView): number;
    /**
     * Writes a `Date` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeDate(valueWriter: BiWriter | BiWriterStream, object: Date): 15 | 11 | 7;
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
    private buildHeader;
    private finalizeBuffers;
    /**
     * Can stip or include the key value in file
     *
     * Can also set your own key.
     *
     * @param {boolean?} EncryptionExcluded - remove key from file
     * @param {number?} Encryptionkey - 32 bit number
     */
    private encrypt;
    /**
     * Compresses data
     */
    private compress;
    /**
     * Creates CRC hash
     */
    private CRC;
}

declare class JPExtData {
    readonly type: number;
    readonly data: Buffer;
    constructor(type: number, data: Buffer);
}
type JPExtensionDecoderType<ContextType> = (data: BiReader | BiReaderStream, decoder: JPDecode<ContextType>, type: number, context: ContextType) => unknown;
type JPExtensionEncoderType<ContextType> = (input: unknown, encoder: JPEncode<ContextType>, context: ContextType) => Buffer | null;
type JPExtensionCodecType<ContextType> = {
    __brand?: ContextType;
    tryToEncode(object: unknown, encoder: JPEncode<ContextType>, context: ContextType): JPExtData | null;
    decode(data: BiReader | BiReaderStream, decoder: JPDecode<ContextType>, type: number, context: ContextType): unknown;
};
type JPExtensionType<ContextType = undefined> = {
    /**
     * Number type to register the extension between 0x00 - 0xCF.
     *
     * 0xDO - 0xFF are reserved for internal use.
     */
    type: number;
    /**
     * Encoding function
     *
     * @param {unknown} input - Your object to type check and encode
     * @param {JPEncode<ContextType>} encoder - class encoder
     * @param {ContextType} context - Context of the class (shouldn't be needed)
     * @returns `Buffer|null`
     */
    encode: JPExtensionEncoderType<ContextType>;
    /**
     * Decoding function
     *
     * @param {BiReader | BiReaderStream} data - BiReader of buffer data.
     * @param {JPDecode<ContextType>} decoder - class decoder
     * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
     * @param {ContextType} context - Context of the class (shouldn't be needed)
     * @returns `YourType`
     */
    decode: JPExtensionDecoderType<ContextType>;
};
declare class JPExtensionCodec<ContextType = undefined> implements JPExtensionCodecType<ContextType> {
    static readonly defaultCodec: JPExtensionCodecType<undefined>;
    __brand?: ContextType;
    private readonly encoders;
    private readonly decoders;
    constructor(extension?: JPExtensionType);
    register(extension: JPExtensionType): void;
    tryToEncode(object: unknown, encoder: JPEncode<ContextType>, context: ContextType): JPExtData | null;
    decode(data: BiReader | BiReaderStream, decoder: JPDecode<ContextType>, type: number, context: ContextType): unknown;
}

/**
 * Options for `JPDecode`
 */
type DecoderOptions<ContextType = undefined> = Readonly<Partial<{
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
}>> & ContextOf<ContextType>;
/**
 * Create with `DecoderOptions`
 */
declare class JPDecode<ContextType = undefined> extends JPBase {
    private readonly extensionCodec;
    private readonly context;
    private readonly mapKeyConverter;
    private readonly stack;
    private stringsList;
    /**
     * Endianness. Defaults to `little`
     */
    endian: endian;
    /**
     * Converts return to valid JSON
     */
    makeJSON: boolean;
    /**
     * Ensures all 64 bit values return as `bigint`
     */
    enforceBigInt: boolean;
    /**
     * File Buffer
     */
    private buffer;
    /**
     * Direct objects for any symbols that were encoded.
     */
    symbolList: symbol[];
    /**
     * If a temp file was needed.
     */
    private tempCreated;
    /**
     * If the file buffer has extensions types in use.
     */
    hasExtensions: boolean;
    /**
     * If the data is acceptable JSON data.
     */
    validJSON: boolean;
    /**
     * Computed CRC32 hash value.
     */
    CRC32Hash: number;
    /**
     * CRC32 Hash on file.
     */
    CRC32OnFile: number;
    /**
     * Set up with basic options.
     *
     * @param {DecoderOptions?} options - options for decoding
     */
    constructor(options?: DecoderOptions<ContextType>);
    private clone;
    /**
     * Basic decoding, will run options that were set in constructor.
     *
     * If passed a `string`, will assume it is a file path to read the file from.
     *
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     *
     * @param bufferOrSourcePath - `Buffer` of the JamPack data or the file path to a JamPack file.
     */
    decode(bufferOrSourcePath: Buffer | ArrayLike<number> | Uint8Array<ArrayBufferLike> | ArrayBufferView | ArrayBufferLike | string): unknown;
    /**
     * Basic decoding, will run options that were set in constructor.
     *
     * If passed a `string`, will assume it is a file path to read the file from.
     *
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     *
     * @async
     * @param bufferOrSourcePath - `Buffer` of the JamPack data or the file path to a JamPack file.
     */
    decodeAsync(bufferOrSourcePath: Buffer | ArrayLike<number> | Uint8Array<ArrayBufferLike> | ArrayBufferView | ArrayBufferLike | string): Promise<unknown>;
    private checkFilePath;
    private testHeader;
    /**
     * Sets up valueReader & strReader. Will decomp and decrypt as well.
     *
     * If a temp file is made, will have to delete after.
     */
    private reinitializeState;
    private setBuffer;
    private createStringList;
    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     *
     * NOTE: This function is for extention use, not direct use. Use `decodeAsync` instead.
     *
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    doDecodeAsync(bufferOrReader: Buffer | BiReader | BiReaderStream): Promise<unknown>;
    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     *
     * NOTE: This function is for extention use, not direct use. Use `decode` instead.
     *
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    doDecodeSync(bufferOrReader: Buffer | BiReader | BiReaderStream): unknown;
    private pushMapState;
    private pushObjectState;
    private pushArrayState;
    private pushSetState;
    private readString;
    private decodeExtension;
    private decrypt;
}

export { JPDecode, JPEncode, JPExtData, JPExtType, JPExtensionCodec, JPType };
export type { BigValue, DecoderOptions, EncoderOptions, JPExtensionCodecType, JPExtensionDecoderType, JPExtensionEncoderType, JPExtensionType, endian };
