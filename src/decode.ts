import fs from "fs";
import { Crypt, CRC32 } from './hash.js';
import { BiReader, BiReaderStream, BiWriterStream } from 'bireader';
import { JPExtensionCodec, JPExtensionCodecType } from "./ext.js";
import {
    VERSION_NUMBER,
    inflateFileSync,
    inflateBuffer,
    endian,
    bit,
    JPType,
    JPExtType,
    MAX_BUFFER,
    JPBase,
    ensureBuffer,
    ContextOf
} from './common.js';

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
function stringifyFix(_this: any, key: any): any {

    if (key === undefined) {
        return "undefined";
    } else if (key instanceof RegExp) {
        const src = key.source;

        const flags = key.flags;

        return { regexSrc: src, regexFlags: flags };
    } else if (typeof key == "symbol") {
        const keyCheck = Symbol.keyFor(key);

        const global = !!keyCheck;

        var keyed = keyCheck ?? key.description;

        keyed = keyed ?? "";

        return { symbolGlobal: global, symbolKey: keyed };
    } else if (key instanceof Set) {
        const array = [];

        for (const item of key) {
            array.push(item);
        }

        return array;
    } else if (key instanceof Map) {
        return Array.from(key.entries());
    } else if (typeof key === "bigint") {
        const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);

        const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);

        if (key >= MIN_SAFE && key <= MAX_SAFE) {
            return Number(key);
        } else {
            return key.toString();
        }
    } else {
        return key;
    }
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

const STATE_ARRAY = "array";

const STATE_SET = "set";

const STATE_MAP_KEY = "map_key";

const STATE_MAP_VALUE = "map_value";

const STATE_OBJECT_KEY = "object_key";

const STATE_OBJECT_VALUE = "object_value";

type MapKeyType = string | number | symbol;

const mapKeyConverter = (key: unknown): MapKeyType => {
    if (typeof key === "string" || typeof key === "number" || typeof key == "symbol") {
        return key;
    }

    throw new Error("The type of key must be string or number but " + typeof key);
};

type StackMapState = {
    type: typeof STATE_MAP_KEY | typeof STATE_MAP_VALUE;

    size: number;

    key: MapKeyType | null;

    readCount: number;

    map: Map<MapKeyType, unknown>;
};

type StackObjectState = {
    type: typeof STATE_OBJECT_KEY | typeof STATE_OBJECT_VALUE;

    size: number;

    key: MapKeyType | null;

    readCount: number;

    object: Record<MapKeyType, unknown>;
};

type StackArrayState = {
    type: typeof STATE_ARRAY;

    size: number;

    array: Array<unknown>;

    position: number;
};

type StackSetState = {
    type: typeof STATE_SET;

    size: number;

    set: Set<unknown>;

    position: number;
};

type StackState = StackSetState | StackArrayState | StackMapState | StackObjectState;

class StackPool {
    private readonly stack: Array<StackState> = [];

    private stackHeadPosition = -1;

    public get length(): number {
        return this.stackHeadPosition + 1;
    };

    public top(): StackState | undefined {
        return this.stack[this.stackHeadPosition];
    };

    public pushArrayState(size: number) {
        const state = this.getUninitializedStateFromPool() as StackArrayState;

        state.type = STATE_ARRAY;

        state.position = 0;

        state.size = size;

        state.array = new Array(size);
    };

    public pushSetState(size: number) {
        const state = this.getUninitializedStateFromPool() as StackSetState;

        state.type = STATE_SET;

        state.position = 0;

        state.size = size;

        state.set = new Set();
    };

    public pushMapState(size: number) {
        const state = this.getUninitializedStateFromPool() as StackMapState;

        state.type = STATE_MAP_KEY;

        state.readCount = 0;

        state.size = size;

        state.map = new Map();
    };

    public pushObjectState(size: number) {
        const state = this.getUninitializedStateFromPool() as StackObjectState;

        state.type = STATE_OBJECT_KEY;

        state.readCount = 0;

        state.size = size;

        state.object = {};
    };

    private getUninitializedStateFromPool() {
        this.stackHeadPosition++;

        if (this.stackHeadPosition === this.stack.length) {
            const partialState: Partial<StackState> = {
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

            this.stack.push(partialState as StackState);
        }

        return this.stack[this.stackHeadPosition];
    };

    public release(state: StackState): void {
        const topStackState = this.stack[this.stackHeadPosition];

        if (topStackState !== state) {
            throw new Error("Invalid stack state. Released state is not on top of the stack.");
        }

        if (state.type === STATE_SET) {
            const partialState = state as Partial<StackSetState>;

            partialState.size = 0;

            partialState.set = undefined;

            partialState.position = 0;

            partialState.type = undefined;
        }

        if (state.type === STATE_ARRAY) {
            const partialState = state as Partial<StackArrayState>;

            partialState.size = 0;

            partialState.array = undefined;

            partialState.position = 0;

            partialState.type = undefined;
        }

        if (state.type === STATE_MAP_KEY || state.type === STATE_MAP_VALUE) {
            const partialState = state as Partial<StackMapState>;

            partialState.size = 0;

            partialState.map = undefined;

            partialState.readCount = 0;

            partialState.type = undefined;
        }

        if (state.type === STATE_OBJECT_KEY || state.type === STATE_OBJECT_VALUE) {
            const partialState = state as Partial<StackObjectState>;

            partialState.size = 0;

            partialState.object = undefined;

            partialState.readCount = 0;

            partialState.type = undefined;
        }

        this.stackHeadPosition--;
    };

    public reset(): void {
        this.stack.length = 0;

        this.stackHeadPosition = -1;
    };
};

/**
 * Create with `DecoderOptions`
 */
export class JPDecode<ContextType = undefined> extends JPBase {
    private readonly extensionCodec: JPExtensionCodecType<ContextType>;

    private readonly context: ContextType;

    private readonly mapKeyConverter = mapKeyConverter;

    private readonly stack = new StackPool();

    private stringsList: string[] = [];

    /**
     * Endianness. Defaults to `little`
     */
    endian: endian = "little";

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
    private buffer: Buffer | null = null;

    /**
     * Direct objects for any symbols that were encoded.
     */
    symbolList: symbol[] = [];

    /**
     * If a temp file was needed.
     */
    private tempCreated = false;

    /**
     * If the file buffer has extensions types in use.
     */
    hasExtensions = false;

    /**
     * If the data is acceptable JSON data.
     */
    validJSON = true;

    /**
     * Computed CRC32 hash value.
     */
    CRC32Hash = 0;

    /**
     * CRC32 Hash on file.
     */
    CRC32OnFile = 0;

    /**
     * Set up with basic options.
     * 
     * @param {DecoderOptions?} options - options for decoding
     */
    constructor(options?: DecoderOptions<ContextType>) {
        super();

        this.extensionCodec = options?.extensionCodec ?? (JPExtensionCodec.defaultCodec as JPExtensionCodecType<ContextType>);

        this.context = (options as { context: ContextType } | undefined)?.context as ContextType; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined

        this.keysArray = options?.keysArray ? options.keysArray : [];

        this.encryptionKey = options?.encryptionKey ? options.encryptionKey : 0;

        this.enforceBigInt = options?.enforceBigInt ? options.enforceBigInt : false;

        this.makeJSON = options?.makeJSON ? options.makeJSON : false;
    };

    private clone(): JPDecode<ContextType> {
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
        } as any);
    };

    /**
     * Basic decoding, will run options that were set in constructor.
     * 
     * If passed a `string`, will assume it is a file path to read the file from.
     * 
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     * 
     * @param bufferOrSourcePath - `Buffer` of the JamPack data or the file path to a JamPack file.
     */
    public decode(bufferOrSourcePath: Buffer | ArrayLike<number> | Uint8Array<ArrayBufferLike> | ArrayBufferView | ArrayBufferLike | string): unknown {
        if (this.entered) {
            const instance = this.clone();

            return instance.decode(bufferOrSourcePath);
        }

        if (typeof bufferOrSourcePath != "string") {
            this.setBuffer(bufferOrSourcePath);
        } else {
            this.fileName = bufferOrSourcePath;

            this.checkFilePath(this.fileName);
        }

        try {
            this.entered = true;

            this.reinitializeState();

            if (this.valueReader == null) {
                this.throwError(" No value reader set. " + this.fileName);
            }

            this.stringsList = this.createStringList() as string[];

            const object = this.doDecodeSync(this.valueReader);

            if(this.tempCreated){
                (this.valueReader as BiReaderStream).deleteFile(); 
            
                this.valueReader.close();
            }

            if(this.makeJSON && !this.validJSON){
                return JSON.parse(JSON.stringify(object, stringifyFix));
            }

            return object;
        } catch (err) {
            console.error(err);

            return;
        } finally {
            this.entered = false;
        }
    };

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
    public async decodeAsync(bufferOrSourcePath: Buffer | ArrayLike<number> | Uint8Array<ArrayBufferLike> | ArrayBufferView | ArrayBufferLike | string): Promise<unknown> {
        try {
            return this.decode(bufferOrSourcePath);
        } catch (err) {
            console.error(err);

            return;
        }
    };

    private checkFilePath(filePath: string): void {
        var biTest: BiReaderStream | BiReader = new BiReaderStream(filePath);

        const testBuffer = biTest.extract(40);

        biTest.close();

        biTest = new BiReader(testBuffer);

        this.testHeader(biTest);

        biTest.close();

        if(!this.useStream){
            this.buffer = fs.readFileSync(filePath);
        }
    };

    private testHeader(br: BiReaderStream | BiReader) {
        const MAGICS = br.uint16;

        if (!(MAGICS == 0x504A || MAGICS == 0x4A50)) {
            this.throwError(` File magics incorrect. Expecting 0x504A or 0x4A50, but got 0x${MAGICS.toString(16).padStart(4, "0")} ` + this.fileName);
        }

        if (MAGICS == 0x4A50) {
            this.endian = "big";
        }

        const V_MAJOR = br.uint8;

        const V_MINOR = br.uint8;

        this.HEADER_SIZE = br.uint8;

        this.LargeFile = br.bit1 as bit;

        this.Compressed = br.bit1 as bit;

        this.Crc32 = br.bit1 as bit;

        this.Encrypted = br.bit1 as bit;

        this.EncryptionExcluded = br.bit1 as bit;

        this.KeyStripped = br.bit1 as bit;

        br.bit1;  // FLAG6

        br.bit1;  // FLAG7

        br.uint8;  // RESV_6 FLAG8-15

        br.uint8;  // RESV_7 FLAG16-23

        this.VALUE_SIZE = br.uint64;

        this.STR_SIZE = br.uint64;

        this.DATA_SIZE = br.uint64;

        const V_NUMBER = parseFloat(`${V_MAJOR}.${V_MINOR}`);

        if (V_NUMBER > VERSION_NUMBER) {
            this.addError(` File was encoded in a more advanced version of this package which may cause issues. Package: ${VERSION_NUMBER} - File: ${V_NUMBER} ` + this.fileName);
        }

        if (this.LargeFile && (br.size > MAX_BUFFER || (this.STR_SIZE + this.VALUE_SIZE) > MAX_BUFFER)) {
            this.useStream = true;
        }

        if (this.EncryptionExcluded && this.encryptionKey == 0) {
            this.throwError(' The encryption key is not included in the file and the key was not set in the decoder. Can not decode. ' + this.fileName);
        }

        if (this.KeyStripped && this.keysArray.length == 0) {
            this.throwError(' The keysArray was removed from the file and not set in the decoder. Can not decode. ' + this.fileName);
        }
        // extra headers
        if (this.Crc32) {
            this.CRC32 = br.uint32;
            this.CRC32OnFile = this.CRC32;
        }

        if (this.Encrypted && !this.EncryptionExcluded) {
            this.encryptionKey = br.uint32;
        }
    };

    /**
     * Sets up valueReader & strReader. Will decomp and decrypt as well.
     * 
     * If a temp file is made, will have to delete after.
     */
    private reinitializeState() {
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
                } else {
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
                } else {
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

                    compReader.overwrite(tempcompWriter.read(0,tempcompWriter.offset), true);

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
                    const buffer = this.compReader.read(position, Math.min(CHUNK_SIZE, this.compReader.size - position)) as Buffer;

                    if (buffer.length == 0) break;

                    crc = CRC32(buffer, crc);

                    position += buffer.length;
                }

                this.CRC32Hash = crc >>> 0;

                if (this.CRC32Hash != this.CRC32OnFile) {
                    this.addError(` File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32OnFile} but got ${this.CRC32Hash}. ` + this.fileName);
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
            } else {
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
                this.addError(` File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${totalSize}. ` + this.fileName);
            }
        } else {
            if (this.buffer == null) {
                this.throwError(" Buffer not set. " + this.fileName);
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
                const data = this.compReader.data as Buffer;

                this.CRC32Hash = CRC32(data, 0) >>> 0;

                if (this.CRC32Hash != this.CRC32OnFile) {
                    this.addError(` File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32OnFile} but got ${this.CRC32Hash}. ` + this.fileName);
                }
            }

            if (this.VALUE_SIZE + this.STR_SIZE != BigInt(this.compReader.size)) {
                this.addError(` File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${this.compReader.size}. ` + this.fileName);
            }

            this.valueReader = new BiReader(this.compReader.extract(Number(this.VALUE_SIZE), true));

            this.valueReader.endian = this.endian;

            this.strReader = new BiReader(this.compReader.extract(Number(this.STR_SIZE), true));

            this.strReader.endian = this.endian;
        }
    };

    private setBuffer(buffer: Buffer | ArrayLike<number> | ArrayBufferView | ArrayBufferLike): void {
        this.buffer = ensureBuffer(buffer);

        this.fileReader = new BiReader(this.buffer);

        this.testHeader(this.fileReader);

        this.fileReader.close();

        this.fileReader = null;
    };

    private createStringList() {
        if (this.strReader == null) {
            this.throwError(" string reader not set. " + this.fileName);
        }

        DECODE: while (true) {
            const headByte = this.strReader.ubyte;

            let object: unknown;

            if ((headByte >= JPType.ARRAY_0 && headByte <= JPType.ARRAY_15) || // arrays
                (headByte >= JPType.ARRAY8 && headByte <= JPType.ARRAY32)
            ) {
                var size = 0;

                if (headByte <= JPType.ARRAY_15) {
                    size = headByte - JPType.ARRAY_0;
                } else if (headByte === JPType.ARRAY8) {
                    size = this.strReader.ubyte;
                } else if (headByte === JPType.ARRAY16) {
                    size = this.strReader.uint16;
                } else if (headByte === JPType.ARRAY32) {
                    size = this.strReader.uint32;
                }

                if (size !== 0) {
                    this.pushArrayState(size);

                    continue DECODE;
                } else {
                    object = [];
                }
            } else if ((headByte >= JPType.STR_0 && headByte <= JPType.STR_15) || // strings
                (headByte >= JPType.STR8 && headByte <= JPType.STR32)
            ) {
                var size = 0;

                if (headByte <= JPType.STR_15) {
                    size = headByte - JPType.STR_0;
                } else if (headByte === JPType.STR8) {
                    size = this.strReader.ubyte;
                } else if (headByte === JPType.STR16) {
                    size = this.strReader.uint16;
                } else if (headByte === JPType.STR32) {
                    size = this.strReader.uint32;
                }

                object = this.strReader.string({ length: size });
            } else {
                this.throwError(` Invalid data in string area. 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }

            const stack = this.stack;

            while (stack.length > 0) {
                // arrays
                const state = stack.top()!;

                if (state.type === STATE_ARRAY) {
                    state.array[state.position] = object;

                    state.position++;

                    if (state.position === state.size) {
                        object = state.array;

                        stack.release(state);
                    } else {
                        continue DECODE;
                    }
                } else {
                    this.throwError(' Should only have an array in the string data, found type ' + state.type + " in file " + this.fileName);
                }
            }

            return object;
        }
    };

    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     * 
     * NOTE: This function is for extention use, not direct use. Use `decodeAsync` instead.
     * 
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    async doDecodeAsync(bufferOrReader: Buffer | BiReader | BiReaderStream): Promise<unknown>{
        var reader = bufferOrReader;
        
        if(reader instanceof Buffer){
            reader = new BiReader(reader);

            reader.endian = this.endian;
        }

        if(!(reader instanceof BiReader || reader instanceof BiReaderStream) || reader == null){
            this.throwError(" Value reader not set. " + this.fileName);
        }

        if(this.strReader == null){
            this.throwError(" String reader not set. " + this.fileName);
        }

        try{
            return this.doDecodeSync(reader);
        } catch (err){
            throw new Error(err);
        }
    };

    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     * 
     * NOTE: This function is for extention use, not direct use. Use `decode` instead.
     * 
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    doDecodeSync(bufferOrReader: Buffer | BiReader | BiReaderStream): unknown {
        var reader = bufferOrReader;

        if(reader instanceof Buffer){
            reader = new BiReader(reader);

            reader.endian = this.endian;
        }

        if(!(reader instanceof BiReader || reader instanceof BiReaderStream) || reader == null){
            this.throwError(" Value reader not set. " + this.fileName);
        }

        if(this.strReader == null){
            this.throwError(" String reader not set. " + this.fileName);
        }

        reader = reader as BiReader;
    
        let object: unknown;

        DECODE: while (true) {
            const headByte: number = reader.ubyte;
            
            if (headByte < JPType.OBJECT_0) {
                // positive fixint 0x00 - 0x7f
                object = headByte;
            } else if (headByte < JPType.ARRAY_0) {
                // fix object 0x80 - 0x8f
                const size = headByte - 0x80;

                if (size !== 0) {
                    this.pushObjectState(size);

                    continue DECODE;
                } else {
                    object = {};
                }
            } else if (headByte < JPType.KEY_0) {
                //fixarray
                const size = headByte - 0x90;

                if (size !== 0) {
                    this.pushArrayState(size);

                    continue DECODE;
                } else {
                    object = [];
                }
            } else if (headByte < JPType.STR_0) {
                //fixkey (only used in stripping)
                const index = headByte - 0xA0;

                if (!this.keysArray[index]) {
                    this.addError( `Did not find key value for index ` + index + " in file " + this.fileName);
                }

                object = this.keysArray[index];
            } else if (headByte < JPType.NULL) {
                //fixstr
                const index = headByte - 0xB0;

                if (this.stringsList[index] === undefined) {
                    this.addError(` Did not find string value for index ` + index + " in file " + this.fileName);
                }

                object = this.stringsList[index];
            } else if (headByte == JPType.NULL) {
                object = null;
            } else if (headByte == JPType.UNDEFINED) {
                object = undefined;
                this.validJSON = false;
            } else if (headByte == JPType.BOOL_FALSE) {
                object = false;
            } else if (headByte == JPType.BOOL_TRUE) {
                object = true;
            } else if (headByte == JPType.FINISHED ||
                headByte == JPType.UNUSED_C6
            ) {
                return object;
            } else if(headByte == JPType.LIST_END){
                const state = this.stack.top()!;

                if(state.type != undefined){
                    if(state.type == STATE_ARRAY){
                        object = state.array;
                    } else if(state.type == STATE_OBJECT_KEY || state.type == STATE_OBJECT_VALUE){
                        object = state.object;
                    } else if(state.type == STATE_MAP_KEY || state.type == STATE_MAP_VALUE){
                        object = state.map;
                    }

                    this.stack.release(state);
                }

                return object;
            } else if (headByte <= JPType.OBJECT32) {
                // non-fix object
                var size = 0;

                if (headByte === JPType.OBJECT8) {
                    size = reader.ubyte;
                } else if (headByte === JPType.OBJECT16) {
                    size = reader.uint16;
                } else if (headByte === JPType.OBJECT32) {
                    size = reader.uint32;
                }

                if (size !== 0) {
                    this.pushObjectState(size);

                    continue DECODE;
                } else {
                    object = {};
                }
            } else if (headByte === JPType.FLOAT32) {
                object = reader.float;
            } else if (headByte === JPType.FLOAT64) {
                object = reader.doublefloat;
            } else if (headByte === JPType.UINT_8) {
                object = reader.uint8;
            } else if (headByte === JPType.UINT_16) {
                object = reader.uint16;
            } else if (headByte === JPType.UINT_32) {
                object = reader.uint32;
            } else if (headByte === JPType.UINT_64) {
                object = reader.uint64; 
                if(this.enforceBigInt){
                    object = BigInt(object as number);
                }
                if(typeof object === "bigint"){
                    this.validJSON = false;
                }
            } else if (headByte === JPType.INT_8) {
                object = reader.int8;
            } else if (headByte === JPType.INT_16) {
                object = reader.int16;
            } else if (headByte === JPType.INT_32) {
                object = reader.int32;
            } else if (headByte === JPType.INT_64) {
                object = reader.int64; 
                if(this.enforceBigInt){
                    object = BigInt(object as number);
                }
                if(typeof object === "bigint"){
                    this.validJSON = false;
                }
            } else if (headByte <= JPType.KEY32) {
                // nonfix key
                var index = 0;

                if (headByte === JPType.KEY8) {
                    index = reader.ubyte;
                } else if (headByte === JPType.KEY16) {
                    index = reader.uint16;
                } else if (headByte === JPType.KEY32) {
                    index = reader.uint32;
                }

                if (!this.keysArray[index]) {
                    this.addError(` Did not find key value for index ` + index + " in file " + this.fileName);
                }

                object = this.keysArray[index];
            } else if (headByte <= JPType.STR32) {
                // non-fix string
                var index = 0;

                if (headByte === JPType.STR8) {
                    index = reader.ubyte;
                } else if (headByte === JPType.STR16) {
                    index = reader.uint16;
                } else if (headByte === JPType.STR32) {
                    index = reader.uint32;
                }

                if (this.stringsList[index] === undefined) {
                    this.addError(` Did not find string value for index ` + index + " in file " + this.fileName);
                }

                object = this.stringsList[index];
            } else if (headByte <= JPType.ARRAY32) {
                // non-fix array
                var size = 0;

                if (headByte === JPType.ARRAY8) {
                    size = reader.ubyte;
                } else if (headByte === JPType.ARRAY16) {
                    size = reader.uint16;
                } else if (headByte === JPType.ARRAY32) {
                    size = reader.uint32;
                }

                if (size !== 0) {
                    this.pushArrayState(size);

                    continue DECODE;
                } else {
                    object = [];
                }
            } else if (headByte <= JPType.EXT32) {
                this.hasExtensions = true;

                var size = 0;

                if (headByte === JPType.EXT8) {
                    size = reader.ubyte;
                } else if (headByte === JPType.EXT16) {
                    size = reader.uint16;
                } else if (headByte === JPType.EXT32) {
                    size = reader.uint32;
                }

                const type = reader.ubyte;

                if(type == JPExtType.Maps){
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushMapState(size);

                        continue DECODE;
                    } else {
                        object = new Map();
                    }
                } else if(type == JPExtType.Sets){
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushSetState(size);

                        continue DECODE;
                    } else {
                        object = new Set();
                    }
                } else {
                    object = this.decodeExtension(reader, size, type);
                }
            } else if (headByte > JPType.EXT32) {
                // negative fixint
                object = headByte - 0x100;
            } else {
                this.throwError(` Outside of index error 0x${headByte.toString(16).padStart(2, "0")} `+ this.fileName);
            }

            const stack = this.stack;

            while (stack.length > 0) {
                // arrays and maps
                const state = stack.top()!;
                if (state.type === STATE_ARRAY) {
                    state.array[state.position] = object;

                    state.position++;

                    if (state.position === state.size) {
                        object = state.array;

                        stack.release(state);
                    } else {
                        continue DECODE;
                    }
                } else if (state.type === STATE_SET) {
                    state.set.add(object);

                    state.position++;

                    if (state.position === state.size) {
                        object = state.set;

                        stack.release(state);
                    } else {
                        continue DECODE;
                    }
                } else if (state.type === STATE_OBJECT_KEY) {
                    if (object === "__proto__") {
                        this.throwError(" The key __proto__ is not allowed " + this.fileName);
                    }

                    state.key = this.mapKeyConverter(object);

                    state.type = STATE_OBJECT_VALUE;

                    continue DECODE;
                } else if (state.type === STATE_OBJECT_VALUE) {
                    state.object[state.key!] = object;

                    state.readCount++;

                    if (state.readCount === state.size) {
                        object = state.object;

                        stack.release(state);
                    } else {
                        state.key = null;

                        state.type = STATE_OBJECT_KEY;

                        continue DECODE;
                    }
                } else if (state.type === STATE_MAP_KEY) {
                    if (object === "__proto__") {
                        this.throwError(" The key __proto__ is not allowed " + this.fileName);
                    }

                    state.key = this.mapKeyConverter(object);

                    state.type = STATE_MAP_VALUE;

                    continue DECODE;
                } else if (state.type === STATE_MAP_VALUE) {
                    // it must be `state.type === State.MAP_VALUE` here

                    state.map.set(state.key!, object);

                    state.readCount++;

                    if (state.readCount === state.size) {
                        object = state.map;

                        stack.release(state);
                    } else {
                        state.key = null;

                        state.type = STATE_MAP_KEY;
                        
                        continue DECODE;
                    }
                }
            }
            return object;
        }
    };

    private pushMapState(size: number) {
        this.stack.pushMapState(size);
    };

    private pushObjectState(size: number) {
        this.stack.pushObjectState(size);
    };

    private pushArrayState(size: number) {
        this.stack.pushArrayState(size);
    };

    private pushSetState(size: number) {
        this.stack.pushSetState(size);
    };

    private readString(headByte: number) {
        if (this.valueReader == null) {
            this.throwError(" Value reader not set. " + this.fileName);
        }

        var value = "";

        if ((headByte >= JPType.STR_0 && headByte <= JPType.STR_15) || // strings
            (headByte >= JPType.STR8 && headByte <= JPType.STR32)
        ) {
            var index = 0;

            if (headByte <= JPType.STR_15) {
                index = headByte - JPType.STR_0;
            } else if (headByte === JPType.STR8) {
                index = this.valueReader.ubyte;
            } else if (headByte === JPType.STR16) {
                index = this.valueReader.uint16;
            } else if (headByte === JPType.STR32) {
                index = this.valueReader.uint32;
            }
            if (this.stringsList[index] === undefined) {
                this.addError(` Did not find string value for index ` + index + " in file " + this.fileName);
            } else {
                value = this.stringsList[index];
            }
        }

        return value;
    };

    private decodeExtension(valueReader: BiReader | BiReaderStream, size: number, extType :number): unknown {
        let retValue:unknown, data: Buffer, holder: Uint8Array;

        switch (extType) {
            case JPExtType.Symbol:
                this.validJSON = false;
                // bool and string
                const global = valueReader.ubyte == JPType.BOOL_TRUE ? true : false;

                var headByte = valueReader.ubyte;

                const key = this.readString(headByte);

                retValue = global ? Symbol.for(key) : Symbol(key);

                this.symbolList.push(retValue as symbol);

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
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new BigUint64Array(holder.buffer);

                break;
            case JPExtType.BigInt64Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new BigInt64Array(holder.buffer);

                break;
            case JPExtType.Float64Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Float64Array(holder.buffer);

                break;
            case JPExtType.Float32Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Float32Array(holder.buffer);

                break;
            case JPExtType.Float16Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);
                // not in use yet
                //retValue = new Float16Array(holder.buffer);

                break;
            case JPExtType.Int32Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Int32Array(holder.buffer);

                break;
            case JPExtType.Uint32Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Uint32Array(holder.buffer);

                break;
            case JPExtType.Uint16Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Uint16Array(holder.buffer);

                break;
            case JPExtType.Int16Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Int16Array(holder.buffer);

                break;
            case JPExtType.Int8Array:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Int8Array(holder.buffer);

                break;
            case JPExtType.Uint8Array:
                data = valueReader.extract(size, true) as Buffer;

                retValue = new Uint8Array(data);

                break;
            case JPExtType.Uint8ClampedArray:
                data = valueReader.extract(size, true) as Buffer;

                holder = new Uint8Array(data);

                retValue = new Uint8ClampedArray(holder.buffer);

                break;
            case JPExtType.Buffer:
                retValue = valueReader.extract(size, true);

                retValue = Buffer.from(retValue as Buffer);

                break;
            case JPExtType.Date:
                data = valueReader.extract(size, true) as Buffer;

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
                        this.throwError(` Unrecognized data size for timestamp (expected 4, 8, or 12): ${br.size} in file ` + this.fileName);
                }
                break;
            default:
                break;
        }

        if(retValue == undefined){
            const data = valueReader.extract(size, true) as Buffer;

            const br = new BiReader(data);

            br.endian = this.endian;

            retValue = this.extensionCodec.decode(br, this, extType, this.context);
        }

        return retValue;
    };

    //////////////
    // FINALIZE //
    //////////////

    private decrypt(br?: BiWriterStream, buffer?:Buffer, finalSize?: number) {
        const cypter = new Crypt(this.encryptionKey);


        if (!this.useStream) {
            if(buffer == null){
                this.throwError(" Buffer to decrypt not set. " + this.fileName);
            }

            const decrypted = cypter.decrypt(buffer);

            if(decrypted.length != finalSize){
                this.addError(` Decrypted buffer size of ${decrypted.length} wasn't expected size of ${finalSize}  in file ` + this.fileName);
            }

            return decrypted;
        } else {
            const CHUNK_SIZE = 16;
            
            br.open();

            br.gotoStart();

            var buff = Buffer.alloc(0);

            var data: Buffer;

            let bytesToProcess = br.size;

            let bytesStart = 0;

            let bytesRead = 0;

            let amount = Math.ceil(br.size / CHUNK_SIZE);

            for (let index = 0; index < amount; index++) {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);

                buff = br.read(bytesStart, bytesRead) as Buffer;

                if(index == (amount - 1)) {
                    data = cypter.decrypt_block(buff, true);
                } else {
                    data = cypter.decrypt_block(buff);
                }

                if(data.length != 0){
                    br.overwrite(data, true);
                }

                bytesStart += buff.length;

                bytesToProcess -= buff.length;
            }

            data = cypter.decrypt_final();
    
            if(data.length != 0){
                br.overwrite(data, true);
            }

            br.trim();

            if(br.size != finalSize){
                this.addError(` Decrypted buffer size of ${br.size} wasn't expected size of ${finalSize} in file 1 + this.fileName`);
            }

            return Buffer.alloc(0);
        }
    };
}