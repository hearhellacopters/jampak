import fs from "fs";
import { Crypt, CRC32 } from './hash.js';
import { BiReader, BiReaderStream } from 'bireader';
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
    copyfile,
    ensureBuffer,
    ContextOf
} from './common.js';

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

            makeJSON: this.makeJSON,
            // TODO may need more
        } as any);
    };

    /**
     * Basic decoding, will run options that were set in constructor.
     * 
     * If passed a string, will assume it is a file path to read the file from.
     * 
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     * 
     * @param bufferOrSourcePath - Buffer of the JamPack data or the file path to a JamPack file.
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
                throw new Error("No value reader set.");
            }

            this.stringsList = this.createStringList() as string[];

            const object = this.doDecodeSync(this.valueReader);

            if(this.tempCreated){
                (this.valueReader as BiReaderStream).deleteFile(); 

                this.valueReader.close();
            }

            if(this.makeJSON){
                return JSON.parse(JSON.stringify(object));
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

            const temp = this.fileName + ".comp";

            this.tempCreated = false;

            if (this.Encrypted) {
                // make comp file without header
                copyfile(this.fileName, this.HEADER_SIZE, temp);

                this.tempCreated = true;

                this.decrypt(temp);
            }
            if (this.Compressed) {
                // check if comp file was made
                if (this.tempCreated) {
                    inflateFileSync(temp, temp + ".tmp");

                    fs.renameSync(temp + ".tmp", temp);

                } else {
                    copyfile(this.fileName, this.HEADER_SIZE, temp);

                    this.tempCreated = true;

                    inflateFileSync(temp, temp + ".tmp");

                    fs.renameSync(temp + ".tmp", temp);
                }
            }
            if (this.Crc32) {
                const chunkSize = 0x2000; // 8192 bytes

                var crc = 0;

                var position = this.HEADER_SIZE;

                var ctx: BiReaderStream = this.compReader;

                ctx.goto(this.HEADER_SIZE);
                // If there is a comp file, no header
                if (this.tempCreated) {
                    this.fileReader = new BiReaderStream(temp);

                    this.fileReader.endian = this.endian;

                    ctx.open();

                    position = 0;
                }

                for (; position <= ctx.size;) {
                    const buffer = ctx.read(position, Math.min(chunkSize, ctx.size - position), false);

                    if (buffer.length == 0) break;

                    crc = CRC32(buffer, crc);

                    position += buffer.length;
                }

                if (crc != this.CRC32) {
                    console.warn(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32} but got ${crc}.`);
                }
            }

            var totalSize = 0n;

            if (this.tempCreated) {
                totalSize = BigInt(this.compReader.size);

                this.valueReader = new BiReaderStream(temp);

                this.valueReader.endian = this.endian;

                this.strReader = new BiReaderStream(temp);

                this.strReader.endian = this.endian;

                this.strReader.goto(Number(this.VALUE_SIZE));
            } else {
                totalSize = BigInt(this.compReader.size - this.HEADER_SIZE);

                this.valueReader = new BiReaderStream(this.fileName);

                this.valueReader.endian = this.endian;

                this.valueReader.goto(this.HEADER_SIZE);

                this.strReader = new BiReaderStream(this.fileName);

                this.strReader.endian = this.endian;

                this.strReader.goto(this.HEADER_SIZE + Number(this.VALUE_SIZE));
            }

            if (this.VALUE_SIZE + this.STR_SIZE != totalSize) {
                console.warn(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${totalSize}.`);
            }

            this.compReader.open();

            // Clone the readers.

            this.valueReader.fd = this.compReader.fd;

            this.valueReader.size = this.compReader.size;

            this.valueReader.sizeB = this.compReader.sizeB;

            this.valueReader.maxFileSize = this.compReader.maxFileSize;

            this.strReader.fd = this.compReader.fd;

            this.strReader.size = this.compReader.size;

            this.strReader.sizeB = this.compReader.sizeB;

            this.strReader.maxFileSize = this.compReader.maxFileSize;
        } else {
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
                decomBuffer = this.decrypt("", decomBuffer);

                this.compReader = new BiReader(decomBuffer);

                this.compReader.endian = this.endian;
            }
            if (this.Compressed) {
                decomBuffer = inflateBuffer(this.compReader);

                this.compReader = new BiReader(decomBuffer);

                this.compReader.endian = this.endian;
            }
            if (this.Crc32) {
                const crc = CRC32(this.compReader.data, 0);

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
            throw new Error("string reader not set.");
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
                throw new Error(`Invalid data in string area. 0x${headByte.toString(16).padStart(2, "0")}`);
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
                    throw new Error('Should only have an array in the string data, found type ' + state.type);
                }
            }

            return object;
        }
    };

    private doDecodeSync(br: BiReader | BiReaderStream): unknown {
        if (br == null) {
            throw new Error("Value reader not set.");
        }

        let object: unknown;

        DECODE: while (true) {
            const headByte: number = br.ubyte;
            
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
                    console.warn(`Did not find key value for index ` + index);
                }

                object = this.keysArray[index];
            } else if (headByte < JPType.NULL) {
                //fixstr
                const index = headByte - 0xB0;

                if (this.stringsList[index] === undefined) {
                    console.warn(`Did not find string value for index ` + index);

                    console.debug(this.stringsList);
                }

                object = this.stringsList[index];
            } else if (headByte == JPType.NULL) {
                object = null;
            } else if (headByte == JPType.UNDEFINED) {
                object = undefined;
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
                    size = br.ubyte;
                } else if (headByte === JPType.OBJECT16) {
                    size = br.uint16;
                } else if (headByte === JPType.OBJECT32) {
                    size = br.uint32;
                }

                if (size !== 0) {
                    this.pushObjectState(size);

                    continue DECODE;
                } else {
                    object = {};
                }
            } else if (headByte === JPType.FLOAT32) {
                object = br.float;
            } else if (headByte === JPType.FLOAT64) {
                object = br.doublefloat;
            } else if (headByte === JPType.UINT_8) {
                object = br.uint8;
            } else if (headByte === JPType.UINT_16) {
                object = br.uint16;
            } else if (headByte === JPType.UINT_32) {
                object = br.uint32;
            } else if (headByte === JPType.UINT_64) {
                object = br.uint64; 
                if(this.enforceBigInt){
                     object = BigInt(object as number);
                }
            } else if (headByte === JPType.INT_8) {
                object = br.int8;
            } else if (headByte === JPType.INT_16) {
                object = br.int16;
            } else if (headByte === JPType.INT_32) {
                object = br.int32;
            } else if (headByte === JPType.INT_64) {
                object = br.int64; 
                if(this.enforceBigInt){
                     object = BigInt(object as number);
                }
            } else if (headByte <= JPType.KEY32) {
                // nonfix key
                var index = 0;

                if (headByte === JPType.KEY8) {
                    index = br.ubyte;
                } else if (headByte === JPType.KEY16) {
                    index = br.uint16;
                } else if (headByte === JPType.KEY32) {
                    index = br.uint32;
                }

                if (!this.keysArray[index]) {
                    console.warn(`Did not find key value for index ` + index);
                }

                object = this.keysArray[index];
            } else if (headByte <= JPType.STR32) {
                // non-fix string
                var index = 0;

                if (headByte === JPType.STR8) {
                    index = br.ubyte;
                } else if (headByte === JPType.STR16) {
                    index = br.uint16;
                } else if (headByte === JPType.STR32) {
                    index = br.uint32;
                }

                if (this.stringsList[index] === undefined) {
                    console.warn(`Did not find string value for index ` + index);

                    console.debug(this.stringsList);
                }

                object = this.stringsList[index];
            } else if (headByte <= JPType.ARRAY32) {
                // non-fix array
                var size = 0;

                if (headByte === JPType.ARRAY8) {
                    size = br.ubyte;
                } else if (headByte === JPType.ARRAY16) {
                    size = br.uint16;
                } else if (headByte === JPType.ARRAY32) {
                    size = br.uint32;
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
                    size = br.ubyte;
                } else if (headByte === JPType.EXT16) {
                    size = br.uint16;
                } else if (headByte === JPType.EXT32) {
                    size = br.uint32;
                }

                const type = br.ubyte;

                if(type == JPExtType.Maps){
                    if (size !== 0) {
                        this.pushMapState(size);

                        continue DECODE;
                    } else {
                        object = new Map();
                    }
                } else if(type == JPExtType.Sets){
                    if (size !== 0) {
                        this.pushSetState(size);

                        continue DECODE;
                    } else {
                        object = new Set();
                    }
                } else {
                    object = this.decodeExtension(br, size, type);
                }
            } else if (headByte > JPType.EXT32) {
                // negative fixint
                object = headByte - 0x100;
            } else {
                throw new Error(`Outside of index error 0x${headByte.toString(16).padStart(2, "0")}`);
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
                        throw new Error("The key __proto__ is not allowed");
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
                        throw new Error("The key __proto__ is not allowed");
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
            throw new Error("Value reader not set.");
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
                console.warn(`Did not find string value for index ` + index);

                console.debug(this.stringsList);
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
                // bool and string
                const global = valueReader.ubyte == JPType.BOOL_TRUE ? true : false;

                var headByte = valueReader.ubyte;

                const key = this.readString(headByte);

                retValue = global ? Symbol.for(key) : Symbol(key);

                this.symbolList.push(retValue as symbol);

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
                        const sec = br.uint32le;

                        const nsec = 0;

                        retValue = new Date(sec * 1e3 + nsec / 1e6);

                        break;
                    }
                    case 8: {
                        // timestamp 64 = { nsec30, sec34 }
                        const nsec30AndSecHigh2 = br.uint32le;

                        const secLow32 = br.uint32le;

                        const sec = (nsec30AndSecHigh2 & 0x3) * 0x100000000 + secLow32;

                        const nsec = nsec30AndSecHigh2 >>> 2;

                        retValue = new Date(sec * 1e3 + nsec / 1e6);

                        break;
                    }
                    case 12: {
                        // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
                        const nsec = br.uint32le;
                        
                        const sec = Number(br.int64le);

                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                    }
                    default:
                        throw new Error(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${br.size}`);
                }
                break;
            default:
                break;
        }

        if(retValue == undefined){
            const data = valueReader.extract(size, true) as Buffer;

            const br = new BiReader(data);

            br.endian = this.endian;

            retValue = this.extensionCodec.decode(br, extType, this.context);
        }

        return retValue;
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
            throw new Error(`File magics incorrect. Expecting 0x504A or 0x4A50, but got 0x${MAGICS.toString(16).padStart(4, "0")}`);
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
    };

    //////////////
    // FINALIZE //
    //////////////

    private decrypt(filePath: string, buffer?:Buffer) {
        if (this.fileReader == null) {
            throw new Error("Can't decrypt without file.");
        }

        const cypter = new Crypt(this.encryptionKey);

        if (!this.useStream) {
            if(buffer == null){
                throw new Error("Buffer to decrypt not set.");
            }

            return cypter.decrypt(buffer);
        } else {
            const chunkSize = 16;

            const br = new BiReaderStream(filePath);

            br.endian = this.endian;

            const size = br.size;

            for (let position = 0; position <= size;) {
                const buffer = br.read(position, Math.min(chunkSize, br.size - position));

                if (buffer.length == 0) {
                    br.data = cypter.decrypt_final();
                    
                    br.commit();

                    break;
                }

                br.data = cypter.decrypt_block(buffer) as Buffer;

                br.commit();

                position += buffer.length;

                if (position == size) {
                     br.data = cypter.decrypt_final();

                    br.commit();
                }
            }

            br.trim();

            br.close();

            return Buffer.alloc(0);
        }
    };
}