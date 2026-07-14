import { 
  BiReader, 
  BiReaderAsync, 
  BiWriter,
  BiWriterAsync
 } from "bireader";
import { JPEncode } from './encode.js';
import { JPEncodeAsync } from './encodeAsync.js';
import { JPDecode } from './decode.js';
import { JPDecodeAsync } from './decodeAsync.js';

/**
 * Example number type to register the extension between 0x00 - 0xCF.
 * 
 * 0xDO - 0xFF are reserved for internal use.
 */
const DATE_EXT_TYPE = 0xFF;

/**
 * Example encoding function
 * 
 * @param {unknown} input - Your object to type check and encode
 * @param {JPEncode<ContextType>} encoder - class encoder
 * @param {ContextType} context - Context of the class (shouldn't be needed)
 * @returns {Buffer|null}
 */
function encodeTimestampExtension<ContextType = undefined>(
  input: unknown,
  encoder: JPEncode<ContextType>,
  context: ContextType): Buffer | null {
  // check if the input is the same type, else return null
  // here we are converting a Date object into a Buffer
  if (!(input instanceof Date)) {
    return null;
  } else {
    // now convert the data into a Buffer
    const TIMESTAMP32_MAX_SEC = 0x100000000 - 1; // 32-bit unsigned int

    const TIMESTAMP64_MAX_SEC = 0x400000000 - 1; // 34-bit unsigned int

    const msec = input.getTime();

    const _sec = Math.floor(msec / 1e3);

    const _nsec = (msec - _sec * 1e3) * 1e6;
    // Normalizes { sec, nsec } to ensure nsec is unsigned.
    const nsecInSec = Math.floor(_nsec / 1e9);

    const sec = _sec + nsecInSec;

    const nsec = _nsec - nsecInSec * 1e9;
    // Recommend use is a BiWriter for creating Buffer data
    const bw = new BiWriter(Buffer.alloc(12));

    bw.endian = encoder.endian;

    if (sec >= 0 && nsec >= 0 && sec <= TIMESTAMP64_MAX_SEC) {
      // Here sec >= 0 && nsec >= 0
      if (nsec === 0 && sec <= TIMESTAMP32_MAX_SEC) {
        // timestamp 32 = { sec32 (unsigned) }
        bw.uint32 = sec;

        bw.trim();

        return bw.return() as Buffer;
      } else {
        // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
        const secHigh = sec / 0x100000000;

        const secLow = sec & 0xffffffff;
        // nsec30 | secHigh2
        bw.uint32 = (nsec << 2) | (secHigh & 0x3);
        // secLow32
        bw.uint32 = secLow;

        bw.trim();

        return bw.return() as Buffer;
      }
    } else {
      // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
      bw.uint32 = nsec;

      bw.int64 = BigInt(sec);

      bw.trim();

      return bw.return() as Buffer;
    }
  }
};

/**
 * Example async encoding function
 * 
 * @param {unknown} input - Your object to type check and encode
 * @param {JPEncodeAsync<ContextType>} encoder - class encoder
 * @param {ContextType} context - Context of the class (shouldn't be needed)
 * @returns {Promise<Buffer | null>}
 */
async function encodeTimestampAsyncExtension<ContextType = undefined>(
  input: unknown,
  encoder: JPEncodeAsync<ContextType>,
  context: ContextType): Promise<Buffer | null> {
  // check if the input is the same type, else return null
  // here we are converting a Date object into a Buffer
  if (!(input instanceof Date)) {
    return null;
  } else {
    // now convert the data into a Buffer
    const TIMESTAMP32_MAX_SEC = 0x100000000 - 1; // 32-bit unsigned int

    const TIMESTAMP64_MAX_SEC = 0x400000000 - 1; // 34-bit unsigned int

    const msec = input.getTime();

    const _sec = Math.floor(msec / 1e3);

    const _nsec = (msec - _sec * 1e3) * 1e6;
    // Normalizes { sec, nsec } to ensure nsec is unsigned.
    const nsecInSec = Math.floor(_nsec / 1e9);

    const sec = _sec + nsecInSec;

    const nsec = _nsec - nsecInSec * 1e9;
    // Recommend use is a BiWriter for creating Buffer data
    const bw = new BiWriterAsync(Buffer.alloc(12));

    bw.endian = encoder.endian;

    if (sec >= 0 && nsec >= 0 && sec <= TIMESTAMP64_MAX_SEC) {
      // Here sec >= 0 && nsec >= 0
      if (nsec === 0 && sec <= TIMESTAMP32_MAX_SEC) {
        // timestamp 32 = { sec32 (unsigned) }
        await bw.uint32(sec);

        await bw.trim();

        return await bw.return() as Buffer;
      } else {
        // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
        const secHigh = sec / 0x100000000;

        const secLow = sec & 0xffffffff;
        // nsec30 | secHigh2
        await bw.uint32((nsec << 2) | (secHigh & 0x3));
        // secLow32
        await bw.uint32(secLow);

        await bw.trim();

        return await bw.return() as Buffer;
      }
    } else {
      // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
      await bw.uint32(nsec);

      await bw.int64(BigInt(sec));

      await bw.trim();

      return await bw.return() as Buffer;
    }
  }
};

/**
 * Example decoding function
 * 
 * @param {BiReader<any, any>} reader - BiReader of buffer data.
 * @param {JPDecode<ContextType>} decoder - class decoder
 * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
 * @param {ContextType} context - Context of the class (shouldn't be needed)
 * @returns {Date}
 */
function decodeTimestampExtension<ContextType = undefined>(
  reader: BiReader<any, any>,
  decoder: JPDecode<ContextType>,
  extensionType: number,
  context: ContextType): Date {
    // check if the type matches
    if (extensionType != DATE_EXT_TYPE) {
      throw new Error(`Extension for Date encoding 0x${extensionType.toString(16).padStart(2, "0")} does not match register type 0x${DATE_EXT_TYPE.toString(16).padStart(2, "0")}`);
    }
    // data may be 32, 64, or 96 bits
    switch (reader.size) {
      case 4: {
        // timestamp 32 = { sec32 }
        const sec = reader.uint32le;

        const nsec = 0;

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      case 8: {
        // timestamp 64 = { nsec30, sec34 }
        const nsec30AndSecHigh2 = reader.uint32le;

        const secLow32 = reader.uint32le;

        const sec = (nsec30AndSecHigh2 & 0x3) * 0x100000000 + secLow32;

        const nsec = nsec30AndSecHigh2 >>> 2;

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      case 12: {
        // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
        const nsec = reader.uint32le;

        const sec = Number(reader.int64le);

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      default:
        throw new Error(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${reader.size}`);
    }
};

/**
 * Example decoding function
 * 
 * @param {BiReaderAsync<any, any>} reader - BiReader of buffer data.
 * @param {JPDecodeAsync<ContextType>} decoder - class decoder
 * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
 * @param {ContextType} context - Context of the class (shouldn't be needed)
 * @returns {Promise<Date>}
 */
async function decodeTimestampAsyncExtension<ContextType = undefined>(
  reader: BiReaderAsync<any, any>,
  decoder: JPDecodeAsync<ContextType>,
  extensionType: number,
  context: ContextType): Promise<Date> {
    // check if the type matches
    if (extensionType != DATE_EXT_TYPE) {
      throw new Error(`Extension for Date encoding 0x${extensionType.toString(16).padStart(2, "0")} does not match register type 0x${DATE_EXT_TYPE.toString(16).padStart(2, "0")}`);
    }
    // data may be 32, 64, or 96 bits
    switch (reader.size) {
      case 4: {
        // timestamp 32 = { sec32 }
        const sec = await reader.uint32le();

        const nsec = 0;

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      case 8: {
        // timestamp 64 = { nsec30, sec34 }
        const nsec30AndSecHigh2 = await reader.uint32le();

        const secLow32 = await reader.uint32le();

        const sec = (nsec30AndSecHigh2 & 0x3) * 0x100000000 + secLow32;

        const nsec = nsec30AndSecHigh2 >>> 2;

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      case 12: {
        // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
        const nsec = await reader.uint32le();

        const sec = Number(await reader.int64le());

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      default:
        throw new Error(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${reader.size}`);
    }
};

/**
 * Example object passed to `JPExtensionCodec.register`
 */
export const timestampExtension: JPExtensionType = {
  type: DATE_EXT_TYPE,
  encode: encodeTimestampExtension,
  encodeAsync: encodeTimestampAsyncExtension,
  decode: decodeTimestampExtension,
  decodeAsync: decodeTimestampAsyncExtension
};

export class JPExtData {
  readonly type: number;

  readonly data: Buffer;

  constructor(type: number, data: Buffer) {
    this.type = type;
    this.data = data;
  }
};

export type JPExtensionDecoderAsyncType<ContextType> = (
  data: BiReaderAsync<any, any>,
  decoder: JPDecodeAsync<ContextType>,
  type: number,
  context: ContextType,
) => Promise<unknown>;

export type JPExtensionDecoderType<ContextType> = (
  data: BiReader<any, any>,
  decoder: JPDecode<ContextType>,
  type: number,
  context: ContextType,
) => unknown;

export type JPExtensionEncoderAsyncType<ContextType> = (
  input: unknown,
  encoder: JPEncodeAsync<ContextType>,
  context: ContextType,
) => Promise<Buffer | null>;

export type JPExtensionEncoderType<ContextType> = (
  input: unknown,
  encoder: JPEncode<ContextType>,
  context: ContextType,
) => Buffer | null;

export type JPExtensionCodecType<ContextType> = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  __brand?: ContextType;
  tryToEncode(object: unknown, encoder: JPEncode<ContextType>, context: ContextType,): JPExtData | null;
  tryToEncodeAsync(object: unknown, encoder: JPEncodeAsync<ContextType>, context: ContextType,): Promise<JPExtData | null>;
  decode(data: BiReader<any, any>, decoder: JPDecode<ContextType>, type:number, context: ContextType): unknown;
  decodeAsync(data: BiReaderAsync<any, any>, decoder: JPDecodeAsync<ContextType>, type:number, context: ContextType): Promise<unknown>;
};

export type JPExtensionType<ContextType = undefined> = {
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
   * Async Encoding function
   * 
   * @param {unknown} input - Your object to type check and encode
   * @param {JPEncodeAsync<ContextType>} encoder - class encoder
   * @param {ContextType} context - Context of the class (shouldn't be needed)
   * @returns `Promise<Buffer|null>`
   */
  encodeAsync: JPExtensionEncoderAsyncType<ContextType>;
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
  /**
   * Async Decoding function
   * 
   * @param {BiReader | BiReaderStream} data - BiReader of buffer data.
   * @param {JPDecodeAsync<ContextType>} decoder - class decoder
   * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
   * @param {ContextType} context - Context of the class (shouldn't be needed)
   * @returns `Promise<YourType>`
   */
  decodeAsync: JPExtensionDecoderAsyncType<ContextType>;
};

export class JPExtensionCodec<ContextType = undefined> implements JPExtensionCodecType<ContextType> {
  public static readonly defaultCodec: JPExtensionCodecType<undefined> = new JPExtensionCodec();
  // ensures ExtensionCodecType<X> matches ExtensionCodec<X>
  // this will make type errors a lot more clear
  // eslint-disable-next-line @typescript-eslint/naming-convention
  __brand?: ContextType;

  // custom extensions
  private readonly encoders: Array<JPExtensionEncoderType<ContextType> | undefined | null> = [];

  private readonly encodersAsync: Array<JPExtensionEncoderAsyncType<ContextType> | undefined | null> = [];

  private readonly decoders: Array<JPExtensionDecoderType<ContextType> | undefined | null> = [];

  private readonly decodersAsync: Array<JPExtensionDecoderAsyncType<ContextType> | undefined | null> = [];

  public constructor(extension?: JPExtensionType<ContextType>) {
    if(extension){
      this.register(extension);
    }
  };

  public register(extension: JPExtensionType<ContextType>): void {
    // custom extensions
    if ((extension.type < 0 || extension.type > 0xCF)) {
      throw new Error(`Type EXT number is outside of allowed range (0x0 - 0xCF but got 0x${extension.type.toString(16).padStart(2, "0")})`);
    }
    this.encoders[extension.type] = extension.encode;

    this.decoders[extension.type] = extension.decode;

    this.encodersAsync[extension.type] = extension.encodeAsync;

    this.decodersAsync[extension.type] = extension.decodeAsync;
  };

  public tryToEncode(object: unknown, encoder: JPEncode<ContextType>, context: ContextType): JPExtData | null {
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
  };

  public async tryToEncodeAsync(object: unknown, encoder: JPEncodeAsync<ContextType>, context: ContextType): Promise<JPExtData | null> {
    // custom extensions
    for (let i = 0; i < this.encodersAsync.length; i++) {
      const encodeExt = this.encodersAsync[i];

      if (encodeExt != null) {
        const data = await encodeExt(object, encoder, context);
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
  };

  public decode(data: BiReader<any, any>, decoder: JPDecode<ContextType>, type:number, context: ContextType): unknown {
    const decodeExt = this.decoders[type];

    if (decodeExt) {
      return decodeExt(data, decoder, type, context);
    } else {
      // decode() does not fail, returns ExtData instead.
      return new JPExtData(type, data.data as Buffer);
    }
  }

  public async decodeAsync(data: BiReaderAsync<any, any>, decoder: JPDecodeAsync<ContextType>, type:number, context: ContextType): Promise<unknown> {
    const decodeExt = this.decodersAsync[type];

    if (decodeExt) {
      return await decodeExt(data, decoder, type, context);
    } else {
      // decode() does not fail, returns ExtData instead.
      return new JPExtData(type, data.data as Buffer);
    }
  }
};