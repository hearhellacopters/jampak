import { BiReader, BiReaderStream, BiWriter, BiWriterStream } from "bireader";
import { JPEncode } from './encode.js'

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

        return bw.return as Buffer;
      } else {
        // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
        const secHigh = sec / 0x100000000;

        const secLow = sec & 0xffffffff;
        // nsec30 | secHigh2
        bw.uint32 = (nsec << 2) | (secHigh & 0x3);
        // secLow32
        bw.uint32 = secLow;

        bw.trim();

        return bw.return as Buffer;
      }
    } else {
      // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
      bw.uint32 = nsec;

      bw.int64 = BigInt(sec);

      bw.trim();

      return bw.return as Buffer;
    }
  }
};

/**
 * Example decoding function
 * 
 * @param {BiReader | BiReaderStream} data - BiReader of buffer data.
 * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
 * @param {ContextType} context - Context of the class (shouldn't be needed)
 * @returns {Date}
 */
function decodeTimestampExtension<ContextType = undefined>(
  data: BiReader | BiReaderStream,
  extensionType: number,
  context: ContextType): Date {
    // check if the type matches
    if (extensionType != DATE_EXT_TYPE) {
      throw new Error(`Extension for Date encoding 0x${extensionType.toString(16).padStart(2, "0")} does not match register type 0x${DATE_EXT_TYPE.toString(16).padStart(2, "0")}`);
    }
    // data may be 32, 64, or 96 bits
    switch (data.size) {
      case 4: {
        // timestamp 32 = { sec32 }
        const sec = data.uint32le;

        const nsec = 0;

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      case 8: {
        // timestamp 64 = { nsec30, sec34 }
        const nsec30AndSecHigh2 = data.uint32le;

        const secLow32 = data.uint32le;

        const sec = (nsec30AndSecHigh2 & 0x3) * 0x100000000 + secLow32;

        const nsec = nsec30AndSecHigh2 >>> 2;

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      case 12: {
        // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
        const nsec = data.uint32le;

        const sec = Number(data.int64le);

        return new Date(sec * 1e3 + nsec / 1e6);
      }
      default:
        throw new Error(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${data.size}`);
    }
};

/**
 * Example object passed to `JPExtensionCodec.register`
 */
export const timestampExtension: JPExtensionType = {
  type: DATE_EXT_TYPE,
  encode: encodeTimestampExtension,
  decode: decodeTimestampExtension,
};

export class JPExtData {
  readonly type: number;

  readonly data: Buffer;

  constructor(type: number, data: Buffer) {
    this.type = type;
    this.data = data;
  }
};

export type JPExtensionDecoderType<ContextType> = (
  data: BiReader | BiReaderStream,
  extensionType: number,
  context: ContextType,
) => unknown;

export type JPExtensionEncoderType<ContextType> = (
  input: unknown,
  encoder: JPEncode<ContextType>,
  context: ContextType,
) => Buffer | null;

export type JPExtensionCodecType<ContextType> = {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  __brand?: ContextType;
  tryToEncode(object: unknown, encoder: JPEncode<ContextType>, context: ContextType,): JPExtData | null;
  decode(data: BiReader | BiReaderStream, extType: number, context: ContextType): unknown;
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
   * Decoding function
   * 
   * @param {BiReader | BiReaderStream} data - BiReader of buffer data.
   * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
   * @param {ContextType} context - Context of the class (shouldn't be needed)
   * @returns `YourType`
   */
  decode: JPExtensionDecoderType<ContextType>;
};

export class JPExtensionCodec<ContextType = undefined> implements JPExtensionCodecType<ContextType> {
  public static readonly defaultCodec: JPExtensionCodecType<undefined> = new JPExtensionCodec();
  // ensures ExtensionCodecType<X> matches ExtensionCodec<X>
  // this will make type errors a lot more clear
  // eslint-disable-next-line @typescript-eslint/naming-convention
  __brand?: ContextType;

  // custom extensions
  private readonly encoders: Array<JPExtensionEncoderType<ContextType> | undefined | null> = [];

  private readonly decoders: Array<JPExtensionDecoderType<ContextType> | undefined | null> = [];

  public constructor(extension?: JPExtensionType) {
    if(extension){
      this.register(extension);
    }
  };

  public register(extension: JPExtensionType): void {
    // custom extensions
    if ((extension.type < 0 || extension.type > 0xCF)) {
      throw new Error(`Type EXT number is outside of allowed range (0x0 - 0xCF but got 0x${extension.type.toString(16).padStart(2, "0")})`);
    }
    this.encoders[extension.type] = extension.encode;

    this.decoders[extension.type] = extension.decode;
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

  public decode(data: BiReader | BiReaderStream, type: number, context: ContextType): unknown {
    const decodeExt = this.decoders[type];

    if (decodeExt) {
      return decodeExt(data, type, context);
    } else {
      // decode() does not fail, returns ExtData instead.
      return new JPExtData(type, data.data as Buffer);
    }
  }
};