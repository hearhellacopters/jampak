import fsp from "fs/promises";
import { BiWriterAsync, hexdump } from 'bireader';
import { 
    Crypt, 
    CRC32 
} from './hash.js';
import zlib from 'zlib';
import { Encoder } from 'cbor-x';
import { 
    JPExtensionCodec, 
    JPExtensionCodecType, 
    JPExtData 
} from "./ext.js";
import {
    VERSION_MAJOR,
    VERSION_MINOR,
    deflateBufferAsync,
    isFloat32Safe,
    fileExists,
    endian,
    ubyte,
    uint16,
    JPType,
    JPExtType,
    stringList,
    JPBaseAsync,
    EncoderOptions,
    GROWTHINCREMENT_DEFAULT,
    CHUNK_SIZE
} from './common.js';

/**
 * Create with `EncoderOptions`
 */
export class JPEncodeAsync<ContextType = undefined> extends JPBaseAsync {
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

    useMSGPK = 0;

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

        this.growthIncrement = encodeOptions?.growthIncrement ? encodeOptions.growthIncrement : GROWTHINCREMENT_DEFAULT;

        this.useMSGPK = encodeOptions?.msgpack ? 1: 0;
    };

    private clone(): JPEncodeAsync<ContextType> {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // @ts-ignore
        const clone = new JPEncodeAsync<ContextType>({
            extensionCodec: this.extensionCodec as JPExtensionCodecType<ContextType>,

            context: this.context as ContextType,

            endian: this.endian,

            encrypt: this.Encrypted,

            stripEncryptKey: this.EncryptionExcluded,

            encryptionKey: this.encryptionKey,

            compress: this.Compressed,

            stripKeys: this.KeyStripped,

            CRC32: this.Crc32,

            growthIncrement: this.growthIncrement,

            msgpack: this.useMSGPK
        });

        clone.fileName = this.fileName;

        clone.useFile = this.useFile;

        clone.valueWriterAsync = this.valueWriterAsync;

        clone.strWriterAsync = this.strWriterAsync;

        clone.keysArray = this.keysArray;

        clone.compWriterAsync = this.compWriterAsync;            
        //TODO may need more here
        return clone;
    };

    /**
     * Basic encode, will run options that were set in constructor.
     * 
     * @param {any} object - Data to encode
     * @param {string} filePath - Optional file path to write the file to directly
     * @returns {Buffer}
     */
    public async encode(object: unknown, filePath?: string): Promise<Buffer> {
        if (this.entered) {
            const instance = this.clone();

            return await instance.encode(object, filePath);
        }

        this.fileName = filePath ? filePath : "";

        if (this.fileName != "") {
            this.useFile = true;
        }

        try {
            this.entered = true;

            if(this.useMSGPK){
                const encoder = new Encoder({encodeUndefinedAsNil: true,   variableMapSize:true});

                var data = encoder.encode(object);

                this.VALUE_SIZE = BigInt(data.length);

                this.STR_SIZE = 0;

                this.DATA_SIZE = BigInt(data.length);

                if (this.Crc32) {
                    this.CRC32 = CRC32(data, 0) >>> 0;
                }

                if (this.Compressed) {
                    const buffers = [];

                    let bytesToProcess = data.length;

                    let bytesStart = 0;

                    let bytesRead = 0;

                    do {
                        bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                
                        if (bytesRead > 0) {
                            const chunk = data.subarray(bytesStart, bytesRead);
                
                            const compressed = zlib.deflateSync(chunk);

                            const lenBuf = Buffer.alloc(4);

                            lenBuf.writeUint32LE(compressed.length);
                
                            buffers.push(lenBuf);

                            buffers.push(compressed);
                
                            bytesToProcess -= bytesRead;
                
                            bytesStart += bytesRead;
                        }
                    } while (bytesRead === CHUNK_SIZE);

                    data = Buffer.concat(buffers);

                    this.DATA_SIZE = BigInt(data.length);
                }

                if (this.Encrypted) {
                    const cypter = new Crypt(this.encryptionKey == 0 ? undefined : this.encryptionKey);
                    
                    this.encryptionKey = cypter.key;

                    data = cypter.encrypt(data);
                }

                this.headerBuffer = await this.buildHeader();

                const compBuffer = Buffer.concat([this.headerBuffer, data]);

                if(this.useFile){
                    await fsp.writeFile(this.fileName, compBuffer);
                }

                return compBuffer as Buffer;
            }

            await this.reinitializeState();

            if (this.valueWriterAsync == null || this.strWriterAsync == null) {
                this.throwError("Didn't create writers. " + this.fileName);
            }

            await this.doEncode(this.valueWriterAsync, object, 1);

            await this.valueWriterAsync.ubyte(JPType.FINISHED);

            await this.valueWriterAsync.trim();

            this.VALUE_SIZE = this.valueWriterAsync.size;

            await this.writeStringsData();

            await this.strWriterAsync.ubyte(JPType.FINISHED);

            await this.strWriterAsync.trim();

            this.STR_SIZE = this.strWriterAsync.size;

            if (this.KeyStripped) {
                this.keysArray = this.keyList.getValues();
            }

            await this.finalizeBuffers();

            this.headerBuffer = await this.buildHeader();
            
            if (this.compWriterAsync == null) {
                this.throwError("Didn't create writer. " + this.fileName);
            }
            
            const newOff = BigInt(this.compWriterAsync.size + this.headerBuffer.length);

            await this.compWriterAsync.unshift(this.headerBuffer, false);
            
            await this.compWriterAsync.goto(Number(newOff));

            await this.compWriterAsync.trim();

            await this.compWriterAsync.commit();

            if(this.useFile){
                await this.compWriterAsync.renameFile(this.fileName);

                await this.compWriterAsync.close();

                return Buffer.alloc(0);
            } else {
                return await this.compWriterAsync.getData() as Buffer;
            }
        } catch (err) {
            console.error(err);

            return Buffer.alloc(0);
        } finally {
            this.entered = false;
        }
    };

    private async reinitializeState() {
        if (this.useFile) {
            if(fileExists(this.fileName + ".values")){
                await fsp.unlink(this.fileName + ".values");
            }

            this.valueWriterAsync = new BiWriterAsync(this.fileName + ".values", { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });

            await this.valueWriterAsync.open();

            this.valueWriterAsync.endian = this.endian;

            if(fileExists(this.fileName + ".strings")){
                await fsp.unlink(this.fileName + ".strings");
            }

            this.strWriterAsync = new BiWriterAsync(this.fileName + ".strings", { windowSize: this.growthIncrement,growthIncrement: this.growthIncrement });

            await this.strWriterAsync.open();

            this.strWriterAsync.endian = this.endian;
        } else {
            this.valueWriterAsync = new BiWriterAsync(Buffer.alloc(this.growthIncrement), {growthIncrement: this.growthIncrement });

            this.valueWriterAsync.endian = this.endian;

            this.strWriterAsync = new BiWriterAsync(Buffer.alloc(this.growthIncrement), { growthIncrement: this.growthIncrement });

            this.strWriterAsync.endian = this.endian;
        }
    };

    private async doEncode(valueWriter:BiWriterAsync<any, any>, object: unknown, depth: number) {
        this.depth = depth;

        if (object === null) {
            return await this.encodeNull(valueWriter);
        } else if (object === undefined) {
            return await this.encodeUndefined(valueWriter);
        } else if (typeof object === "boolean") {
            return await this.encodeBoolean(valueWriter, object);
        } else if (typeof object === "number") {
            return await this.encodeNumber(valueWriter, object);
        } else if (typeof object === "string") {
            return await this.encodeString(valueWriter, object, false);
        } else if (typeof object === "bigint") {
            return await this.encodeBigInt64(valueWriter, object);
        } else if (typeof object === "symbol") {
            return await this.encodeSymbol(valueWriter, object); // EXT
        } else {
            // if (typeof object === "object")
            const ext = await this.extensionCodec.tryToEncodeAsync(object, this, this.context);
            
            if (ext != null) {
                return await this.encodeExtension(valueWriter, ext); //EXT
            } else if (Array.isArray(object)) {
                return await this.encodeArray(valueWriter, object, this.depth);
            } else if (object instanceof Map) {
                return await this.encodeMap(valueWriter, object, this.depth); // EXT
            } else if (object instanceof Set) {
                return await this.encodeSet(valueWriter, object, this.depth); // EXT
            } else if (object instanceof RegExp) {
                return await this.encodeRegEx(valueWriter, object); // EXT
            } else if (ArrayBuffer.isView(object) || object instanceof Buffer) {
                return await this.encodeBinary(valueWriter, object); // EXT
            } else if (object instanceof Date) {
                return await this.encodeDate(valueWriter, object); // EXT
            } else if (typeof object === "object") {
                return await this.encodeObject(valueWriter, object as Record<string, unknown>, this.depth);
            } else {
                // function and other special object come here unless extensionCodec handles them.
                this.throwError(`Unrecognized object: ${Object.prototype.toString.apply(object)} ` + this.fileName);
            }
        }

        return;
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
    async encodeObject(valueWriter: BiWriterAsync<any, any>, object: Record<string, unknown>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }
        
        var length = 1;

        const keys = Object.keys(object);

        const size = keys.length;

        if (size < 16) {
            // fixmap
            await valueWriter.ubyte(JPType.OBJECT_0 + size);
        } else if (size < 0x100) {
            // map 8
            await valueWriter.ubyte(JPType.OBJECT8);

            await valueWriter.ubyte(size);

            length++;
        } else if (size < 0x10000) {
            // map 16
            await valueWriter.ubyte(JPType.OBJECT16);

            await valueWriter.ushort(size);

            length += 2;
        } else if (size < 0x100000000) {
            // map 32
            await valueWriter.ubyte(JPType.OBJECT32);

            await valueWriter.uint32(size);

            length += 4;
        } else {
            this.throwError(`Too large map object: ${size} in file ` + this.fileName);
        }

        for (const key of keys) {
            const value = object[key];

            length += await this.encodeString(valueWriter, key, true);

            length += await this.doEncode(valueWriter,  value, depth + 1);

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
    async encodeArray(valueWriter:BiWriterAsync<any, any>, array: Array<unknown>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }

        var length = 1;

        const size = array.length;

        if (size < 16) {
            // fixarray
            await valueWriter.ubyte(JPType.ARRAY_0 + size);
        } else if (size < 0x100) {
            // uint8
            await valueWriter.ubyte(JPType.ARRAY8);

            await valueWriter.ubyte(size);

            length++;
        } else if (size < 0x10000) {
            // array 16
            await valueWriter.ubyte(JPType.ARRAY16);

            await valueWriter.ushort(size);

            length += 2;
        } else if (size < 0x100000000) {
            // array 32
            await valueWriter.ubyte(JPType.ARRAY32);

            await valueWriter.uint32(size);

            length += 4;
        } else {
            this.throwError(`Too large array: ${size} in file ` + this.fileName);
        }

        for (const item of array) {
            length += await this.doEncode(valueWriter, item, depth + 1);
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
    async encodeString(valueWriter:BiWriterAsync<any, any>, string: string, isKey?: boolean) {
        if(isKey == undefined){
            isKey = false;
        }

        var length = 1;

        if (isKey && this.KeyStripped) {
            const index = this.keyList.add(string);

            if (index < 16) {
                await valueWriter.ubyte(JPType.KEY_0 + index);
            } else if (index < 0x100) {
                // uint8
                await valueWriter.ubyte(JPType.KEY8);

                await valueWriter.ubyte(index);

                length++;
            } else if (index < 0x10000) {
                // unit16
                await valueWriter.ubyte(JPType.KEY16);

                await valueWriter.ushort(index);

                length += 2;
            } else if (index < 0x100000000) {
                // unit32
                await valueWriter.ubyte(JPType.KEY32);

                await valueWriter.uint32(index);

                length += 4;
            } else {
                this.throwError(`String index too long: ${index} in file ` + this.fileName);
            }
        } else {
            const index = this.stringList.add(string);

            if (index < 16) {
                await valueWriter.ubyte(JPType.STR_0 + index);
            } else if (index < 0x100) {
                // uint8
                await valueWriter.ubyte(JPType.STR8);

                await valueWriter.ubyte(index);

                length++;
            } else if (index < 0x10000) {
                // unit16
                await valueWriter.ubyte(JPType.STR16);

                await valueWriter.ushort(index);

                length += 2;
            } else if (index < 0x100000000) {
                // unit32
                await valueWriter.ubyte(JPType.STR32);

                await valueWriter.uint32(index);

                length += 4;
            } else {
                this.throwError(`String index too long: ${index} in file ` + this.fileName);
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
    async encodeNull(valueWriter:BiWriterAsync<any, any>) {
        await valueWriter.ubyte(JPType.NULL);

        return 1;
    };

    /**
     * Writes an `undefined` to the buffer
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeUndefined(valueWriter:BiWriterAsync<any, any>) {
        await valueWriter.ubyte(JPType.UNDEFINED);

        return 1;
    };

    /**
     * Writes a `boolean` true or false to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - `true` or `false`
     * @returns The `number` of bytes written
     */
    async encodeBoolean(valueWriter:BiWriterAsync<any, any>, object: boolean) {
        if (object === false) {
            await valueWriter.ubyte(JPType.BOOL_FALSE);
        } else {
            await valueWriter.ubyte(JPType.BOOL_TRUE);
        }

        return 1;
    };

    /**
     * Writes an "finished" byte to the buffer. End the loop when hit if not finished otherwise.
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeFinished(valueWriter:BiWriterAsync<any, any>){
        await valueWriter.ubyte(JPType.FINISHED);

        return 1;
    };

    /**
     * Writes a "list end" byte to the buffer, useful when pulling loose data and don't want to break the whole loop.
     * 
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeListEnd(valueWriter:BiWriterAsync<any, any>){
        await valueWriter.ubyte(JPType.LIST_END);

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
    async encodeNumber(valueWriter:BiWriterAsync<any, any>, number: number) {
        var length = 1;

        if (Number.isSafeInteger(number)) {
            if (number >= 0) {
                if (number < 0x80) {
                    // positive fixint
                    await valueWriter.ubyte(number);
                } else if (number < 0x100) {
                    // uint 8
                    await valueWriter.ubyte(JPType.UINT_8);

                    await valueWriter.ubyte(number);

                    length++;
                } else if (number < 0x10000) {
                    // uint 16
                    await valueWriter.ubyte(JPType.UINT_16);

                    await valueWriter.ushort(number);

                    length += 2;
                } else if (number < 0x100000000) {
                    // uint 32
                    await valueWriter.ubyte(JPType.UINT_32);

                    await valueWriter.uint32(number);

                    length += 4;
                } else {
                    // uint 64
                    await valueWriter.ubyte(JPType.UINT_64);

                    await valueWriter.uint64(number);

                    length += 8;
                }
            } else {
                if (number >= -0x20) {
                    // negative fixint
                    await valueWriter.byte(number);
                } else if (number >= -0x80) {
                    // int 8
                    await valueWriter.ubyte(JPType.INT_8);

                    await valueWriter.byte(number);

                    length++;
                } else if (number >= -0x8000) {
                    // int 16
                    await valueWriter.ubyte(JPType.INT_16);

                    await valueWriter.int16(number);

                    length += 2;
                } else if (number >= -0x80000000) {
                    // int 32
                    await valueWriter.ubyte(JPType.INT_32);

                    await valueWriter.int32(number);

                    length += 4;
                } else {
                    // int 64
                    await valueWriter.ubyte(JPType.INT_64);

                    await valueWriter.int64(number);

                    length += 8;
                }
            }

            return length;
        } else {
            return await this.encodeNumberAsFloat(valueWriter, number);
        }
    };

    /**
     * Writes a `bigint` to the buffer. Always written as a 64 bit value.
     * 
     * @param valueWriter - Writer
     * @param bigint - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeBigInt64(valueWriter:BiWriterAsync<any, any>, bigint: bigint) {
        var length = 0;

        if (bigint >= BigInt(0)) {
            // uint 64
            await valueWriter.ubyte(JPType.UINT_64); length++;

            await valueWriter.uint64(bigint); length += 8;
        } else {
            // int 64
            await valueWriter.ubyte(JPType.INT_64); length++;

            await valueWriter.int64(bigint); length += 8;
        }
        
        return length;
    };

    private async encodeStringHeader(byteLength: number) {
        var length = 1;

        if (this.strWriterAsync == null) {
            this.throwError("Didn't create writer. " + this.fileName);
        }

        if (byteLength < 16) {
            // fixstr
            await this.strWriterAsync.ubyte(JPType.STR_0 + byteLength);
        } else if (byteLength < 0x100) {
            // str 8
            await this.strWriterAsync.ubyte(JPType.STR8);

            await this.strWriterAsync.ubyte(byteLength);

            length++;
        } else if (byteLength < 0x10000) {
            // str 16
            await this.strWriterAsync.ubyte(JPType.STR16);

            await this.strWriterAsync.uint16(byteLength);

            length += 2;
        } else if (byteLength < 0x100000000) {
            // str 32
            await this.strWriterAsync.ubyte(JPType.STR32);

            await this.strWriterAsync.uint32(byteLength);

            length += 4;
        } else {
            this.throwError(`Too long string: ${byteLength} bytes in UTF-8 in file ` + this.fileName);
        }

        return length;
    };

    private async writeString(object: string) {
        if (this.strWriterAsync == null) {
            this.throwError("Didn't create writer. " + this.fileName);
        }

        const encoder = new TextEncoder();

        const encodedString = encoder.encode(object);

        const byteLength = encodedString.length;

        var length = await this.encodeStringHeader(byteLength);

        await this.strWriterAsync.string(object, { length: byteLength });

        return length + byteLength;
    };

    private async writeStringsData() {
        const array = this.stringList.getValues();

        const size = array.length;

        if (this.strWriterAsync == null) {
            this.throwError("Didn't create writer. " + this.fileName);
        }

        if (size < 16) {
            // fixarray
            await this.strWriterAsync.ubyte(JPType.ARRAY_0 + size);
        } else if (size < 0x100) {
            // uint8
            await this.strWriterAsync.ubyte(JPType.ARRAY8);

            await this.strWriterAsync.ubyte(size);
        } else if (size < 0x10000) {
            // array 16
            await this.strWriterAsync.ubyte(JPType.ARRAY16);

            await this.strWriterAsync.ushort(size);
        } else if (size < 0x100000000) {
            // array 32
            await this.strWriterAsync.ubyte(JPType.ARRAY32);

            await this.strWriterAsync.uint32(size);
        } else {
            this.throwError(`String array too large: ${size} in file ` + this.fileName);
        }

        for (let i = 0; i < size; i++) {
            const el = array[i];

            await this.writeString(el);
        }
    };

    private async encodeNumberAsFloat(valueWriter:BiWriterAsync<any, any>, object: number) {
        var length = 1;

        if (isFloat32Safe(object)) {
            // float 32
            await valueWriter.ubyte(JPType.FLOAT32);

            await valueWriter.float(object);

            length += 4;
        } else {
            // float 64
            await valueWriter.ubyte(JPType.FLOAT64);
            
            await valueWriter.dfloat(object);

            length += 8;
        }

        return length;
    };

    ////////////
    //  EXTS  //
    ////////////

    private async encodeExtension(valueWriter:BiWriterAsync<any, any>, ext: JPExtData) {
        const size = ext.data.length;

        var length = size;

        if (size < 0x100) {
            // ext 8
            await valueWriter.ubyte(JPType.EXT8);

            await valueWriter.ubyte(size);

            length += 2;
        } else if (size < 0x10000) {
            // ext 16
            await valueWriter.ubyte(JPType.EXT16);

            await valueWriter.ushort(size);

            length += 3;
        } else if (size < 0x100000000) {
            // ext 32
            await valueWriter.ubyte(JPType.EXT32);

            await valueWriter.uint32(size);

            length += 5;
        } else {
            this.throwError( `Too large extension object: ${size} in file ` + this.fileName);
        }

        await valueWriter.ubyte(ext.type);

        length++;

        await valueWriter.overwrite(ext.data, valueWriter.offset, true);

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
    async encodeMap<K, V>(valueWriter: BiWriterAsync<any, any>, object: Map<K, V>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }

        // Note: length here is the array size of Map, not the buffer size
        var length = 1;

        const keys = [...object.keys()];

        const size = object.size;

        if (size < 0x100) {
            await valueWriter.ubyte(JPType.EXT8);

            await valueWriter.ubyte(size);

            length++;
        } else if (size < 0x10000) {
            await valueWriter.ubyte(JPType.EXT16);

            await valueWriter.ushort(size);

            length += 2;
        } else if (size < 0x100000000) {
            await valueWriter.ubyte(JPType.EXT32);

            await valueWriter.uint32(size);

            length += 4;
        } else {
            this.throwError(`Too large Set length: ${size} in file ` + this.fileName);
        }

        await this.valueWriterAsync.ubyte(JPExtType.Maps); length++;

        for (const key of keys) {
            const value = object.get(key);

            length += await this.doEncode(valueWriter, key, depth + 1); // keys can have any type here

            //this.valueWriter.ubyte = JPType.LIST_END; length++;

            length += await this.doEncode(valueWriter, value, depth + 1);

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
    async encodeSet<T>(valueWriter: BiWriterAsync<any, any>, object: Set<T>, depth?: number) {
        if(depth == undefined){
            depth = this.depth;
        }
        
        // Note: length here is the array size of Set, not the buffer size
        var length = 1;

        const size = object.size;

        if (size < 0x100) {
            await valueWriter.ubyte(JPType.EXT8);

            await valueWriter.ubyte(size);

            length++;
        } else if (size < 0x10000) {
            await valueWriter.ubyte(JPType.EXT16);

            await valueWriter.ushort(size);

            length += 2;
        } else if (size < 0x100000000) {
            await valueWriter.ubyte(JPType.EXT32);

            await valueWriter.uint32(size);

            length += 4;
        } else {
            this.throwError(`Too large Set length: ${size} in file ` + this.fileName);
        }

        await this.valueWriterAsync.ubyte(JPExtType.Sets);

        for (const item of object) {
            length += await this.doEncode(valueWriter, item, depth + 1);

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
    async encodeSymbol(valueWriter: BiWriterAsync<any, any>, object: symbol) {
        const extBuffer = new BiWriterAsync(Buffer.alloc(512));

        const keyCheck = Symbol.keyFor(object);

        const global = !!keyCheck;

        var key = keyCheck ?? object.description;

        key = key ?? "";

        var length = 0;

        length += await this.encodeBoolean(extBuffer, global);

        length += await this.encodeString(extBuffer, key, false);

        await extBuffer.trim();

        if(length < 0x100) {
            await valueWriter.ubyte(JPType.EXT8);

            await valueWriter.ubyte(length);
        } else if (length < 0x10000) {
            await valueWriter.ubyte(JPType.EXT16);

            await valueWriter.ushort(length);
        } else if (length < 0x100000000) {
            await valueWriter.ubyte(JPType.EXT32);

            await valueWriter.uint(length);
        } else {
            this.throwError(`Too large Symbol length: ${length} in file ` + this.fileName);
        }

        await valueWriter.ubyte(JPExtType.Symbol);
        
        const data = await extBuffer.getData() as Buffer

        await valueWriter.overwrite(data, valueWriter.offset, true);
        
        return length;
    };

    /**
     * Writes a `RegEx` to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeRegEx(valueWriter: BiWriterAsync<any, any>, object: RegExp) {
        const extBuffer = new BiWriterAsync(Buffer.alloc(512), { growthIncrement: this.growthIncrement });

        const src = object.source;

        const flags = object.flags;

        var length = 0;

        length += await this.encodeString(extBuffer, src, false);

        length += await this.encodeString(extBuffer, flags, false);

        await extBuffer.trim();

        if(length < 0x100) {
            await valueWriter.ubyte(JPType.EXT8);

            await valueWriter.ubyte(length);
        } else if (length < 0x10000) {
            await valueWriter.ubyte(JPType.EXT16);

            await valueWriter.ushort(length);
        } else if (length < 0x100000000) {
            await valueWriter.ubyte(JPType.EXT32);

            await valueWriter.uint(length);
        } else {
            this.throwError(`Too large RegEx length: ${length} in file ` + this.fileName);
        }

        await valueWriter.ubyte(JPExtType.RegEx);

        const data = await extBuffer.getData();

        await valueWriter.writeUBytes(<unknown> data as number[], true);

        return length;
    };

    /**
     * Writes a `TypedArray` or `Buffer` to the buffer
     * 
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeBinary(valueWriter: BiWriterAsync<any, any>, object: Buffer | ArrayBufferView) {
        var length = 1;

        const byteLength = object.byteLength;

        if (byteLength < 0x100) {
            await valueWriter.ubyte(JPType.EXT8);

            await valueWriter.ubyte(byteLength);

            length++;
        } else if (byteLength < 0x10000) {
            await valueWriter.ubyte(JPType.EXT16);

            await valueWriter.ushort(byteLength);

            length += 2;
        } else if (byteLength < 0x100000000) {
            await valueWriter.ubyte(JPType.EXT32);

            await valueWriter.uint32(byteLength);

            length += 4;
        } else {
            this.throwError(`Buffer ranged too large. ${byteLength} in file ` + this.fileName);
        }

        if (object instanceof Buffer) {
            await valueWriter.ubyte(JPExtType.Buffer); length++;

            await valueWriter.overwrite(object, valueWriter.offset, true);

            length += object.length;
        } else {
            if (object instanceof Int8Array) {
                await valueWriter.ubyte(JPExtType.Int8Array);
            } else if (object instanceof Uint8Array) {
                await valueWriter.ubyte(JPExtType.Uint8Array);
            } else if (object instanceof Uint8ClampedArray) {
                await valueWriter.ubyte(JPExtType.Uint8ClampedArray);
            } else if (object instanceof Int16Array) {
                await valueWriter.ubyte(JPExtType.Int16Array);
            } else if (object instanceof Uint16Array) {
                await valueWriter.ubyte(JPExtType.Uint16Array);
            } else if (object instanceof Int32Array) {
                await valueWriter.ubyte(JPExtType.Int32Array);
            } else if (object instanceof Uint32Array) {
                await valueWriter.ubyte(JPExtType.Uint32Array);
            } else if (object instanceof Float32Array) {
                await valueWriter.ubyte(JPExtType.Float32Array);
            } else if (object instanceof Float64Array) {
                await valueWriter.ubyte(JPExtType.Float64Array);
            } else if (object instanceof BigInt64Array) {
                await valueWriter.ubyte(JPExtType.BigInt64Array);
            } else if (object instanceof BigUint64Array) {
                await valueWriter.ubyte(JPExtType.BigUint64Array);
                // @ts-ignore
            } else if(object instanceof Float16Array){
                await valueWriter.ubyte(JPExtType.Float16Array);
            } else {
                this.throwError('Unknown Buffer type in file ' + this.fileName);
            }

            length++;

            const uData = new Uint8Array(object.buffer);

            await valueWriter.overwrite(uData, valueWriter.offset, true);

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
    async encodeDate(valueWriter:BiWriterAsync<any, any>, object: Date) {
        const TIMESTAMP32_MAX_SEC = 0x100000000 - 1; // 32-bit unsigned int

        const TIMESTAMP64_MAX_SEC = 0x400000000 - 1; // 34-bit unsigned int

        const msec = object.getTime();

        const _sec = Math.floor(msec / 1e3);

        const _nsec = (msec - _sec * 1e3) * 1e6;
        // Normalizes { sec, nsec } to ensure nsec is unsigned.
        const nsecInSec = Math.floor(_nsec / 1e9);

        const sec = _sec + nsecInSec;

        const nsec = _nsec - nsecInSec * 1e9;

        await valueWriter.ubyte(JPType.EXT8);

        if (sec >= 0 && nsec >= 0 && sec <= TIMESTAMP64_MAX_SEC) {
            // Here sec >= 0 && nsec >= 0
            if (nsec === 0 && sec <= TIMESTAMP32_MAX_SEC) {
                // timestamp 32 = { sec32 (unsigned) }

                await valueWriter.ubyte(4);

                await valueWriter.ubyte(JPExtType.Date);

                await valueWriter.uint32(sec >>> 0);

                return 7;
            } else {
                await valueWriter.ubyte(8);

                await valueWriter.ubyte(JPExtType.Date);
                // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
                const secHigh = sec / 0x100000000;

                const secLow = sec & 0xffffffff;
                // nsec30 | secHigh2
                await valueWriter.uint32(((nsec << 2) | (secHigh & 0x3)) >>> 0);
                // secLow32
                await valueWriter.uint32(secLow >>> 0);

                return 11;
            }
        } else {
            // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
            await valueWriter.ubyte(12);

            await valueWriter.ubyte(JPExtType.Date);

            await valueWriter.uint32(nsec >>> 0);

            await valueWriter.int64(sec);

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
    private async buildHeader(endian?: endian): Promise<Buffer> {
        if (endian) {
            this.endian = endian;
        }

        if (BigInt(this.HEADER_SIZE) + this.DATA_SIZE > BigInt(0x100000000)) {
            this.LargeFile = 1;
        }

        const bw = new BiWriterAsync(Buffer.alloc(this.HEADER_SIZE), { growthIncrement: this.growthIncrement });

        bw.endian = this.endian;

        await bw.uint16(this.MAGIC);

        await bw.uint8(this.VERSION_MAJOR);

        await bw.uint8(this.VERSION_MINOR);

        await bw.uint8(this.HEADER_SIZE);

        await bw.bit1(this.LargeFile);

        await bw.bit1(this.Compressed);

        await bw.bit1(this.Crc32);

        await bw.bit1(this.Encrypted);

        if (this.Encrypted == 0) this.EncryptionExcluded = 0;

        await bw.bit1(this.EncryptionExcluded);

        await bw.bit1(this.KeyStripped);

        await bw.bit1(this.useMSGPK);

        await bw.bit1(0);  // FLAG7

        await bw.uint8(0); // RESV_6 FLAG8-15

        await bw.uint8(0); // RESV_7 FLAG16-23

        await bw.uint64(this.VALUE_SIZE);

        await bw.uint64(this.STR_SIZE);

        await bw.uint64(this.DATA_SIZE);

        if (this.Crc32) {
            await bw.uint32(this.CRC32);
        }

        if (this.Encrypted && !this.EncryptionExcluded) {
            await bw.uint32(this.encryptionKey);
        }

        this.headerBuffer = await bw.getData() as Buffer;

        return this.headerBuffer;
    };

    private async finalizeBuffers() {
        if (this.strWriterAsync == null || this.valueWriterAsync == null) {
            this.throwError("Didn't create writers. " + this.fileName);
        }

        const stringData = await this.strWriterAsync.getData();

        await this.valueWriterAsync.trim();

        await this.valueWriterAsync.push(stringData, true);
        
        await this.valueWriterAsync.trim();
        
        await this.strWriterAsync.deleteFile();

        this.compWriterAsync = this.valueWriterAsync;

        this.DATA_SIZE = BigInt(this.compWriterAsync.size);

        if (this.Crc32) {
            await this.CRC();
        }

        if (this.Compressed) {
            await this.compress();

            this.DATA_SIZE = BigInt(this.compWriterAsync.size);
        }

        if (this.Encrypted) {
            await this.encrypt(this.EncryptionExcluded ? true : false, this.encryptionKey == 0 ? undefined : this.encryptionKey);
        }

        return;
    };

    /**
     * Can stip or include the key value in file 
     * 
     * Can also set your own key.
     * 
     * @param {boolean?} EncryptionExcluded - remove key from file
     * @param {number?} Encryptionkey - 32 bit number
     */
    private async encrypt(EncryptionExcluded?: boolean, Encryptionkey?: number) {
        this.Encrypted = 1;

        this.EncryptionExcluded = EncryptionExcluded ? 1 : 0;

        if (this.compWriterAsync == null) {
            this.throwError("Writer not created for encryption. " + this.fileName);
        }

        const cypter = new Crypt(Encryptionkey);

        this.encryptionKey = cypter.key;

        const srcData = await this.compWriterAsync.getData() as Buffer;
        
        const cryptBuffer = cypter.encrypt(srcData);

        await this.compWriterAsync.close();

        await this.compWriterAsync.open();

        await this.compWriterAsync.overwrite(cryptBuffer, 0, true);

        await this.compWriterAsync.trim();
        
        return this.compWriterAsync.size;
    };

    /**
     * Compresses data
     */
    private async compress() {
        this.Compressed = 1;

        if (this.compWriterAsync == null) {
            this.throwError("Writer not created for compression. " + this.fileName);
        }
        
        this.compWriterAsync.gotoStart();

        const compBuffer = await deflateBufferAsync(this.compWriterAsync);

        await this.compWriterAsync.close();

        await this.compWriterAsync.open();

        await this.compWriterAsync.overwrite(compBuffer, 0, true);

        await this.compWriterAsync.trim();

        return this.compWriterAsync.size;
    };

    /**
     * Creates CRC hash
     */
    private async CRC() {
        this.Crc32 = 1;

        if (this.compWriterAsync == null) {
            this.throwError("Writer not created for CRC. " + this.fileName);
        }

        const data = await this.compWriterAsync.getData() as Buffer;

        this.CRC32 = CRC32(data, 0) >>> 0;

        return;
    };
}