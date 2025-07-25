import { Crypt, CRC32 } from './hash.js';
import { BiWriter, BiWriterStream } from 'bireader';
import { JPExtensionCodec, JPExtensionCodecType, JPExtData } from "./ext.js";
import {
    VERSION_MAJOR,
    VERSION_MINOR,
    deflateFileSync,
    deflateBuffer,
    isFloat32Safe,
    endian,
    ubyte,
    uint16,
    uint32,
    JPType,
    JPExtType,
    stringList,
    JPBase,
    ContextOf
} from './common.js';

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
    }>
> &
    ContextOf<ContextType>;

/**
 * Create with `EncoderOptions`
 */
export class JPEncode<ContextType = undefined> extends JPBase {
    private readonly extensionCodec: JPExtensionCodecType<ContextType>;

    private readonly context: ContextType;

    private stringList = new stringList();

    private keyList = new stringList();

    private depth = 0;

    ////////////////
    // CONSTANTS  //
    ////////////////

    /**
     * JP or PJ
     */
    MAGIC: uint16 = 0x504A;

    /**
     * Endianness. Defaults to ``little``
     */
    endian: endian = "little";

    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MAJOR(): ubyte {
        return VERSION_MAJOR;
    };

    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MINOR(): ubyte {
        return VERSION_MINOR;
    };

    CRC32Hash = 0;

    /**
     * Set up with basic options
     * 
     * @param {EncoderOptions?} encodeOptions - options for encoding
     */
    constructor(encodeOptions?: EncoderOptions<ContextType>) {
        super();

        this.extensionCodec = encodeOptions?.extensionCodec ?? (JPExtensionCodec.defaultCodec as JPExtensionCodecType<ContextType>);

        this.context = (encodeOptions as { context: ContextType } | undefined)?.context as ContextType; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined

        this.endian = encodeOptions?.endian ? encodeOptions.endian : "little";

        this.Encrypted = encodeOptions?.encrypt ? 1 : 0;

        this.EncryptionExcluded = encodeOptions?.stripEncryptKey ? 1 : 0;

        this.encryptionKey = encodeOptions?.encryptionKey ? encodeOptions.encryptionKey : 0;

        this.Compressed = encodeOptions?.compress ? 1 : 0;

        this.KeyStripped = encodeOptions?.stripKeys ? 1 : 0;

        this.Crc32 = encodeOptions?.CRC32 ? 1 : 0;
    };

    private clone() {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // eslint-disable-next-line @typescript-eslint/no-unsafe-argument
        return new JPEncode<ContextType>({
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
        } as any);
    };

    /**
     * Basic encode, will run options that were set in constructor.
     * 
     * @param {any} object - Data to encode
     * @param {string} filePath - Optional file path to write the file to directly
     * @returns {Buffer}
     */
    public encode(object: unknown, filePath?: string): Buffer {
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
                this.throwError(" Didn't create writers. " + this.fileName);
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
                this.throwError(" Didn't create writer. " + this.fileName);
            }

            if (!this.useStream) {
                const compBuffer = this.compWriter.data;

                return Buffer.concat([this.headerBuffer, compBuffer]);
            } else {
                const fileFile = new BiWriterStream(this.fileName);

                fileFile.overwrite(this.headerBuffer,true);

                fileFile.overwrite(this.compWriter.read(0,this.compWriter.size),true);

                this.compWriter.deleteFile();
                // dummy buffer
                return Buffer.alloc(0);
            }
        } catch (err) {
            console.error(err);

            return Buffer.alloc(0);
        } finally {
            this.entered = false;
        }
    };

    private reinitializeState() {
        if (this.useStream) {
            this.valueWriter = new BiWriterStream(this.fileName + ".values", { extendBufferSize: 2048 });

            this.valueWriter.endian = this.endian;

            this.strWriter = new BiWriterStream(this.fileName + ".strings", { extendBufferSize: 2048 });

            this.strWriter.endian = this.endian;
        } else {
            this.valueWriter = new BiWriter(Buffer.alloc(2048), { extendBufferSize: 2048 });

            this.valueWriter.endian = this.endian;

            this.strWriter = new BiWriter(Buffer.alloc(2048), { extendBufferSize: 2048 });

            this.strWriter.endian = this.endian;
        }
    };

    private doEncode(valueWriter:BiWriter|BiWriterStream, object: unknown, depth: number) {
        this.depth = depth;

        if (object === null) {
            return this.encodeNull(valueWriter);
        } else if (object === undefined) {
            return this.encodeUndefined(valueWriter);
        } else if (typeof object === "boolean") {
            return this.encodeBoolean(valueWriter, object);
        } else if (typeof object === "number") {
            return this.encodeNumber(valueWriter, object);
        } else if (typeof object === "string") {
            return this.encodeString(valueWriter, object, false);
        } else if (typeof object === "bigint") {
            return this.encodeBigInt64(valueWriter, object);
        } else if (typeof object === "symbol") {
            return this.encodeSymbol(valueWriter, object); // EXT
        } else {
            // if (typeof object === "object")
            const ext = this.extensionCodec.tryToEncode(object, this, this.context);

            if (ext != null) {
                return this.encodeExtension(valueWriter, ext); //EXT
            } else if (Array.isArray(object)) {
                return this.encodeArray(valueWriter, object, this.depth);
            } else if (object instanceof Map) {
                return this.encodeMap(valueWriter, object, this.depth); // EXT
            } else if (object instanceof Set) {
                return this.encodeSet(valueWriter, object, this.depth); // EXT
            } else if (object instanceof RegExp) {
                return this.encodeRegEx(valueWriter, object); // EXT
            } else if (ArrayBuffer.isView(object) || object instanceof Buffer) {
                return this.encodeBinary(valueWriter, object); // EXT
            } else if (object instanceof Date) {
                return this.encodeDate(valueWriter, object); // EXT
            } else if (typeof object === "object") {
                return this.encodeObject(valueWriter, object as Record<string, unknown>, this.depth);
            } else {
                // function and other special object come here unless extensionCodec handles them.
                this.throwError(` Unrecognized object: ${Object.prototype.toString.apply(object)} ` + this.fileName);
            }
        }
    };

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
    encodeObject(valueWriter: BiWriter|BiWriterStream, object: Record<string, unknown>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }
        
        var length = 1;

        const keys = Object.keys(object);

        const size = keys.length;

        if (size < 16) {
            // fixmap
            valueWriter.ubyte = JPType.OBJECT_0 + size;
        } else if (size < 0x100) {
            // map 8
            valueWriter.ubyte = JPType.OBJECT8;

            valueWriter.ubyte = size;

            length++;
        } else if (size < 0x10000) {
            // map 16
            valueWriter.ubyte = JPType.OBJECT16;

            valueWriter.ushort = size;

            length += 2;
        } else if (size < 0x100000000) {
            // map 32
            valueWriter.ubyte = JPType.OBJECT32;

            valueWriter.uint32 = size;

            length += 4;
        } else {
            this.throwError(` Too large map object: ${size} in file ` + this.fileName);
        }

        for (const key of keys) {
            const value = object[key];

            length += this.encodeString(valueWriter, key, true);

            length += this.doEncode(valueWriter,  value, depth + 1);

        }
        return length;
    };

    /**
     * Writes an `Array` to the buffer as `Array<unknown>`
     * 
     * @param valueWriter - Writer
     * @param array - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeArray(valueWriter:BiWriter|BiWriterStream, array: Array<unknown>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }

        var length = 1;

        const size = array.length;

        if (size < 16) {
            // fixarray
            valueWriter.ubyte = JPType.ARRAY_0 + size;
        } else if (size < 0x100) {
            // uint8
            valueWriter.ubyte = JPType.ARRAY8;

            valueWriter.ubyte = size;

            length++;
        } else if (size < 0x10000) {
            // array 16
            valueWriter.ubyte = JPType.ARRAY16;

            valueWriter.ushort = size;

            length += 2;
        } else if (size < 0x100000000) {
            // array 32
            valueWriter.ubyte = JPType.ARRAY32;

            valueWriter.uint32 = size;

            length += 4;
        } else {
            this.throwError(` Too large array: ${size} in file ` + this.fileName);
        }

        for (const item of array) {
            length += this.doEncode(valueWriter, item, depth + 1);
        }

        return length;
    };

    /**
     * Writes a `string` to the buffer's string section.
     * 
     * @param valueWriter - Writer
     * @param string - Data to encode
     * @param isKey If the string is used a an Object key. Only used when `stripKeys` is enabled.
     * @returns The `number` of bytes written
     */
    encodeString(valueWriter:BiWriter|BiWriterStream, string: string, isKey?: boolean) {
        if(isKey == undefined){
            isKey = false;
        }

        var length = 1;

        if (isKey && this.KeyStripped) {
            const index = this.keyList.add(string);

            if (index < 16) {
                valueWriter.ubyte = JPType.KEY_0 + index;
            } else if (index < 0x100) {
                // uint8
                valueWriter.ubyte = JPType.KEY8;

                valueWriter.ubyte = index;

                length++;
            } else if (index < 0x10000) {
                // unit16
                valueWriter.ubyte = JPType.KEY16;

                valueWriter.ushort = index;

                length += 2;
            } else if (index < 0x100000000) {
                // unit32
                valueWriter.ubyte = JPType.KEY32;

                valueWriter.ushort = index;

                length += 4;
            } else {
                this.throwError(` String index too long: ${index} in file ` + this.fileName);
            }
        } else {
            const index = this.stringList.add(string);

            if (index < 16) {
                valueWriter.ubyte = JPType.STR_0 + index;
            } else if (index < 0x100) {
                // uint8
                valueWriter.ubyte = JPType.STR8;

                valueWriter.ubyte = index;

                length++;
            } else if (index < 0x10000) {
                // unit16
                valueWriter.ubyte = JPType.STR16;

                valueWriter.ushort = index;

                length += 2;
            } else if (index < 0x100000000) {
                // unit32
                valueWriter.ubyte = JPType.STR32;

                valueWriter.ushort = index;

                length += 4;
            } else {
                this.throwError(` String index too long: ${index} in file ` + this.fileName);
            }
        }

        return length;
    };

    /**
     * Writes a `null` to the buffer
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeNull(valueWriter:BiWriter|BiWriterStream) {
        valueWriter.ubyte = JPType.NULL;

        return 1;
    };

    /**
     * Writes an `undefined` to the buffer
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeUndefined(valueWriter:BiWriter|BiWriterStream) {
        valueWriter.ubyte = JPType.UNDEFINED;

        return 1;
    };

    /**
     * Writes a `boolean` true or false to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - `true` or `false`
     * @returns The `number` of bytes written
     */
    encodeBoolean(valueWriter:BiWriter|BiWriterStream, object: boolean) {
        if (object === false) {
            valueWriter.ubyte = JPType.BOOL_FALSE;
        } else {
            valueWriter.ubyte = JPType.BOOL_TRUE;
        }

        return 1;
    };

    /**
     * Writes an "finished" byte to the buffer. End the loop when hit if not finished otherwise.
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeFinished(valueWriter:BiWriter|BiWriterStream){
        valueWriter.ubyte = JPType.FINISHED;

        return 1;
    };

    /**
     * Writes a "list end" byte to the buffer, useful when pulling loose data and don't want to break the whole loop.
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeListEnd(valueWriter:BiWriter|BiWriterStream){
        valueWriter.ubyte = JPType.LIST_END;

        return 1;
    };

    /**
     * Writes a `number` to the buffer . Computes the right byte size base on value.
     * 
     * Notes: Use `encodeBigInt64` for `bigint` types.
     * 
     * @param valueWriter - Writer
     * @param number - Data to encode
     * @returns The `number` of bytes written
     */
    encodeNumber(valueWriter:BiWriter|BiWriterStream, number: number) {
        var length = 1;

        if (Number.isSafeInteger(number)) {
            if (number >= 0) {
                if (number < 0x80) {
                    // positive fixint
                    valueWriter.ubyte = number;
                } else if (number < 0x100) {
                    // uint 8
                    valueWriter.ubyte = JPType.UINT_8;

                    valueWriter.ubyte = number;

                    length++;
                } else if (number < 0x10000) {
                    // uint 16
                    valueWriter.ubyte = JPType.UINT_16;

                    valueWriter.ushort = number;

                    length += 2;
                } else if (number < 0x100000000) {
                    // uint 32
                    valueWriter.ubyte = JPType.UINT_32;

                    valueWriter.uint = number;

                    length += 4;
                } else {
                    // uint 64
                    valueWriter.ubyte = JPType.UINT_64;

                    valueWriter.uint64 = number;

                    length += 8;
                }
            } else {
                if (number >= -0x20) {
                    // negative fixint
                    valueWriter.byte = number;
                } else if (number >= -0x80) {
                    // int 8
                    valueWriter.ubyte = JPType.INT_8;

                    valueWriter.byte = number;

                    length++;
                } else if (number >= -0x8000) {
                    // int 16
                    valueWriter.ubyte = JPType.INT_16;

                    valueWriter.int16 = number;

                    length += 2;
                } else if (number >= -0x80000000) {
                    // int 32
                    valueWriter.ubyte = JPType.INT_32;

                    valueWriter.int32 = number;

                    length += 4;
                } else {
                    // int 64
                    valueWriter.ubyte = JPType.INT_64;

                    valueWriter.int64 = number;

                    length += 8;
                }
            }

            return length;
        } else {
            return this.encodeNumberAsFloat(valueWriter, number);
        }
    };

    /**
     * Writes a `bigint` to the buffer. Always written as a 64 bit value.
     * 
     * @param valueWriter - Writer
     * @param bigint - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBigInt64(valueWriter:BiWriter|BiWriterStream, bigint: bigint) {
        var length = 0;

        if (bigint >= BigInt(0)) {
            // uint 64
            valueWriter.ubyte = JPType.UINT_64; length++;

            valueWriter.uint64 = bigint; length += 8;
        } else {
            // int 64
            valueWriter.ubyte = JPType.INT_64; length++;

            valueWriter.int64 = bigint; length += 8;
        }

        return length;
    };

    private encodeStringHeader(byteLength: number) {
        var length = 1;

        if (this.strWriter == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }

        if (byteLength < 16) {
            // fixstr
            this.strWriter.ubyte = JPType.STR_0 + byteLength;
        } else if (byteLength < 0x100) {
            // str 8
            this.strWriter.ubyte = JPType.STR8;

            this.strWriter.ubyte = byteLength;

            length++;
        } else if (byteLength < 0x10000) {
            // str 16
            this.strWriter.ubyte = JPType.STR16;

            this.strWriter.uint16 = byteLength;

            length += 2;
        } else if (byteLength < 0x100000000) {
            // str 32
            this.strWriter.ubyte = JPType.STR32;

            this.strWriter.uint32 = byteLength;

            length += 4;
        } else {
            this.throwError(` Too long string: ${byteLength} bytes in UTF-8 in file ` + this.fileName);
        }
        return length;
    };

    private writeString(object: string) {
        if (this.strWriter == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }

        const encoder = new TextEncoder();

        const encodedString = encoder.encode(object);

        const byteLength = encodedString.length;

        var length = this.encodeStringHeader(byteLength);

        this.strWriter.string(object, { length: byteLength });

        return length + byteLength;
    };

    private writeStringsData() {
        const array = this.stringList.getValues();

        const size = array.length;

        if (this.strWriter == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }

        if (size < 16) {
            // fixarray
            this.strWriter.ubyte = JPType.ARRAY_0 + size;
        } else if (size < 0x100) {
            // uint8
            this.strWriter.ubyte = JPType.ARRAY8;

            this.strWriter.ubyte = size;
        } else if (size < 0x10000) {
            // array 16
            this.strWriter.ubyte = JPType.ARRAY16;

            this.strWriter.ushort = size;
        } else if (size < 0x100000000) {
            // array 32
            this.strWriter.ubyte = JPType.ARRAY32;

            this.strWriter.uint32 = size;
        } else {
            this.throwError(` String array too large: ${size} in file ` + this.fileName);
        }

        for (let i = 0; i < size; i++) {
            const el = array[i];

            this.writeString(el);
        }
    };

    private encodeNumberAsFloat(valueWriter:BiWriter|BiWriterStream, object: number) {
        var length = 1;

        if (isFloat32Safe(object)) {
            // float 32
            valueWriter.ubyte = JPType.FLOAT32;

            valueWriter.float = object;

            length += 4;
        } else {
            // float 64
            valueWriter.ubyte = JPType.FLOAT64;

            valueWriter.dfloat = object;

            length += 8;
        }

        return length;
    };

    ////////////
    //  EXTS  //
    ////////////

    private encodeExtension(valueWriter:BiWriter|BiWriterStream, ext: JPExtData) {
        const size = ext.data.length;

        var length = size;

        if (size < 0x100) {
            // ext 8
            valueWriter.ubyte = JPType.EXT8;

            valueWriter.ubyte = size;

            length += 2;
        } else if (size < 0x10000) {
            // ext 16
            valueWriter.ubyte = JPType.EXT16;

            valueWriter.ushort = size;

            length += 3;
        } else if (size < 0x100000000) {
            // ext 32
            valueWriter.ubyte = JPType.EXT32;

            valueWriter.uint32 = size;

            length += 5;
        } else {
            this.throwError( `Too large extension object: ${size} in file ` + this.fileName);
        }

        valueWriter.ubyte = ext.type;

        length++;

        valueWriter.overwrite(ext.data, true);

        return length;
    };

    /**
     * Writes a `Map` to the buffer as `Map<key, value>`
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeMap<K, V>(valueWriter: BiWriter | BiWriterStream, object: Map<K, V>, depth?: number) {
        if(depth == undefined){
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
        } else if (size < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;

            valueWriter.ushort = size;

            length += 2;
        } else if (size < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;

            valueWriter.uint32 = size;

            length += 4;
        } else {
            this.throwError(` Too large Set length: ${size} in file ` + this.fileName);
        }

        this.valueWriter.ubyte = JPExtType.Maps; length++;

        for (const key of keys) {
            const value = object.get(key);

            length += this.doEncode(valueWriter, key, depth + 1); // keys can have any type here

            //this.valueWriter.ubyte = JPType.LIST_END; length++;

            length += this.doEncode(valueWriter, value, depth + 1);

            //this.valueWriter.ubyte = JPType.LIST_END; length++;
        }

        return length;
    };

    /**
     * Writes a `Set` to the buffer as `Set<type>`
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeSet<T>(valueWriter: BiWriter | BiWriterStream, object: Set<T>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }
        
        // Note: length here is the array size of Set, not the buffer size
        var length = 1;

        const size = object.size;

        if (size < 0x100) {
            valueWriter.ubyte = JPType.EXT8;

            valueWriter.ubyte = size;

            length++;
        } else if (size < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;

            valueWriter.ushort = size;

            length += 2;
        } else if (size < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;

            valueWriter.uint32 = size;

            length += 4;
        } else {
            this.throwError(` Too large Set length: ${size} in file ` + this.fileName);
        }

        this.valueWriter.ubyte = JPExtType.Sets;

        for (const item of object) {
            length += this.doEncode(valueWriter, item, depth + 1);

            // this.valueWriter.ubyte = JPType.LIST_END; length++;
        }

        return length;
    };

    /**
     * Writes a `symbol` to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeSymbol(valueWriter: BiWriter | BiWriterStream, object: symbol) {
        const extBuffer = new BiWriter(Buffer.alloc(512));

        const keyCheck = Symbol.keyFor(object);

        const global = !!keyCheck;

        var key = keyCheck ?? object.description;

        key = key ?? "";

        var length = 0;

        length += this.encodeBoolean(extBuffer, global);

        length += this.encodeString(extBuffer, key, false);

        extBuffer.trim();

        if(length < 0x100) {
            valueWriter.ubyte = JPType.EXT8;

            valueWriter.ubyte = length;
        } else if (length < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;

            valueWriter.ushort = length;
        } else if (length < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;

            valueWriter.uint = length;
        } else {
            this.throwError(` Too large Symbol length: ${length} in file ` + this.fileName);
        }

        valueWriter.ubyte = JPExtType.Symbol;

        valueWriter.overwrite(extBuffer.return as Buffer, true);

        return length;
    };

    /**
     * Writes a `RegEx` to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeRegEx(valueWriter: BiWriter | BiWriterStream, object: RegExp) {
        const extBuffer = new BiWriter(Buffer.alloc(512));

        const src = object.source;

        const flags = object.flags;

        var length = 0;

        length += this.encodeString(extBuffer, src, false);

        length += this.encodeString(extBuffer, flags, false);

        extBuffer.trim();

        if(length < 0x100) {
            valueWriter.ubyte = JPType.EXT8;

            valueWriter.ubyte = length;
        } else if (length < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;

            valueWriter.ushort = length;
        } else if (length < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;

            valueWriter.uint = length;
        } else {
            this.throwError(` Too large RegEx length: ${length} in file ` + this.fileName);
        }

        valueWriter.ubyte = JPExtType.RegEx;

        valueWriter.overwrite(extBuffer.return as Buffer, true);

        return length;
    };

    /**
     * Writes a `TypedArray` or `Buffer` to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBinary(valueWriter: BiWriter|BiWriterStream, object: Buffer | ArrayBufferView) {
        var length = 1;

        const byteLength = object.byteLength;

        if (byteLength < 0x100) {
            valueWriter.ubyte = JPType.EXT8;

            valueWriter.ubyte = byteLength;

            length++;
        } else if (byteLength < 0x10000) {
            valueWriter.ubyte = JPType.EXT16;

            valueWriter.ushort = byteLength;

            length += 2;
        } else if (byteLength < 0x100000000) {
            valueWriter.ubyte = JPType.EXT32;

            valueWriter.uint32 = byteLength;

            length += 4;
        } else {
            this.throwError(` Buffer ranged too large. ${byteLength} in file ` + this.fileName);
        }

        if (object instanceof Buffer) {
            valueWriter.ubyte = JPExtType.Buffer; length++;

            valueWriter.overwrite(object, true);

            length += object.length;
        } else {
            if (object instanceof Int8Array) {
                valueWriter.ubyte = JPExtType.Int8Array;
            } else if (object instanceof Uint8Array) {
                valueWriter.ubyte = JPExtType.Uint8Array;
            } else if (object instanceof Uint8ClampedArray) {
                valueWriter.ubyte = JPExtType.Uint8ClampedArray;
            } else if (object instanceof Int16Array) {
                valueWriter.ubyte = JPExtType.Int16Array;
            } else if (object instanceof Uint16Array) {
                valueWriter.ubyte = JPExtType.Uint16Array;
            } else if (object instanceof Int32Array) {
                valueWriter.ubyte = JPExtType.Int32Array;
            } else if (object instanceof Uint32Array) {
                valueWriter.ubyte = JPExtType.Uint32Array;
            } else if (object instanceof Float32Array) {
                valueWriter.ubyte = JPExtType.Float32Array;
                //} else if(object instanceof Float16Array){
                // not active yet
                //    valueWriter.ubyte = JPExtType.Float16Array;
            } else if (object instanceof Float64Array) {
                valueWriter.ubyte = JPExtType.Float64Array;
            } else if (object instanceof BigInt64Array) {
                valueWriter.ubyte = JPExtType.BigInt64Array;
            } else if (object instanceof BigUint64Array) {
                valueWriter.ubyte = JPExtType.BigUint64Array;
            } else {
                this.throwError(' Unknown Buffer type in file ' + this.fileName);
            }

            length++;

            const uData = new Uint8Array(object.buffer);

            valueWriter.overwrite(uData, true);

            length += uData.length;
        }

        return length;
    };

    /**
     * Writes a `Date` to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeDate(valueWriter:BiWriter | BiWriterStream, object: Date) {
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

                valueWriter.ubyte  = JPExtType.Date;

                valueWriter.uint32 = sec >>> 0;

                return 7;
            } else {
                valueWriter.ubyte = 8;

                valueWriter.ubyte  = JPExtType.Date;
                // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
                const secHigh = sec / 0x100000000;

                const secLow = sec & 0xffffffff;
                // nsec30 | secHigh2
                valueWriter.uint32 = ((nsec << 2) | (secHigh & 0x3)) >>> 0;
                // secLow32
                valueWriter.uint32 = secLow >>> 0;

                return 11;
            }
        } else {
            // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
            valueWriter.ubyte = 12;

            valueWriter.ubyte  = JPExtType.Date;

            valueWriter.uint32 = nsec >>> 0;

            valueWriter.int64 = sec;

            return 15;
        }
    };

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
    private buildHeader(endian?: endian): Buffer {
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

        if (this.Encrypted == 0) this.EncryptionExcluded = 0;

        bw.bit1 = this.EncryptionExcluded;

        bw.bit1 = this.KeyStripped;

        bw.bit1 = 0;  // FLAG6

        bw.bit1 = 0;  // FLAG7

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

        this.headerBuffer = bw.get as Buffer;

        return this.headerBuffer;
    };

    private finalizeBuffers() {
        if (this.strWriter == null || this.valueWriter == null) {
            this.throwError(" Didn't create writers. " + this.fileName);
        }
        if (!this.useStream) {
            this.valueWriter.trim();

            this.strWriter.trim();

            const stringData = this.strWriter.data;

            this.valueWriter.overwrite(stringData,true);

            this.compWriter = this.valueWriter;

            this.compWriter.trim();
        } else {
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
    };

    /**
     * Can stip or include the key value in file 
     * 
     * Can also set your own key.
     * 
     * @param {boolean?} EncryptionExcluded - remove key from file
     * @param {number?} Encryptionkey - 32 bit number
     */
    private encrypt(EncryptionExcluded?: boolean, Encryptionkey?: number) {
        this.Encrypted = 1;

        this.EncryptionExcluded = EncryptionExcluded ? 1 : 0;

        if (this.compWriter == null) {
            this.throwError(" Writer not created for encryption. " + this.fileName);
        }

        const cypter = new Crypt(Encryptionkey);

        this.encryptionKey = cypter.key;

        if (!this.useStream) {
            const compBuffer = cypter.encrypt(this.compWriter.data as Buffer);

            this.compWriter = new BiWriter(compBuffer);

            return this.compWriter.size;
        } else {
            const CHUNK_SIZE = 16; // 16 bytes at a time

            this.compWriter.gotoStart();

            var data: Buffer;

            var buffer = Buffer.alloc(0);

            let bytesToProcess = Number(this.DATA_SIZE);

            let bytesStart = 0;

            let bytesRead = 0;

            let amount = Math.ceil(this.compWriter.size / CHUNK_SIZE);

            for (let index = 0; index < amount; index++) {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);

                buffer = this.compWriter.read(bytesStart, bytesRead) as Buffer;

                if(index == (amount - 1)) {
                    data = cypter.encrypt_block(buffer, true);
                } else {
                    data = cypter.encrypt_block(buffer);
                }

                if(data.length != 0){
                    this.compWriter.overwrite(data, true);
                }

                bytesStart += buffer.length;

                bytesToProcess -= buffer.length;
            }

            data = cypter.encrypt_final();

            if(data.length != 0){
                this.compWriter.overwrite(data, true);
            }

            this.compWriter.trim();

            return this.compWriter.size;
        }
    };

    /**
     * Compresses data
     */
    private compress() {
        this.Compressed = 1;

        if (this.compWriter == null) {
            this.throwError(" Writer not created for compression. " + this.fileName);
        }

        if (!this.useStream) {
            this.compWriter.gotoStart();

            const compBuffer = deflateBuffer(this.compWriter);

            this.compWriter = new BiWriter(compBuffer);

            this.compWriter.gotoEnd();
        } else {
            const temp = this.fileName + ".comp.tmp";

            const tempcompWriter = new BiWriterStream(temp);

            tempcompWriter.open();

            deflateFileSync(this.compWriter as BiWriterStream, tempcompWriter);

            this.compWriter.gotoStart();

            this.compWriter.overwrite(tempcompWriter.read(0,tempcompWriter.offset), true);

            this.compWriter.trim();

            tempcompWriter.deleteFile();
        }
    };

    /**
     * Creates CRC hash
     */
    private CRC() {
        this.Crc32 = 1;

        if (this.compWriter == null) {
            this.throwError(" Writer not created for CRC. " + this.fileName);
        }

        if (!this.useStream) {
            const data = this.compWriter.data as Buffer;

            this.CRC32 = CRC32(data, 0) >>> 0;

            return;
        } else {
            let crc = 0;

            const CHUNK_SIZE = 0x2000; // 8192 bytes

            for (let position = 0; position <= this.compWriter.size;) {
                const buffer = this.compWriter.read(position, Math.min(CHUNK_SIZE, this.compWriter.size - position)) as Buffer;

                if (buffer.length == 0) break;

                crc = CRC32(buffer, crc);

                position += buffer.length;
            }

            this.CRC32 = crc >>> 0;

            this.CRC32Hash = this.CRC32;
        }
    };
}