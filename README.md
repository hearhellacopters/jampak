# JamPak for Node/JavaScript/TypeScript

<img src="./img/JamPak.png" width="300px"/>

**JamPak** is an efficient file storage solution specifically made for both JavaScript and TypeScript data types in Node.js with a focus on accuracy, expandability, security, and performance. Includes compact storage of all JSON types as well as `TypedArrays`, `Maps`, `Sets`, `Dates`, `Symbols` and more! This library uses a heavily modified implementation of [**MessagePack**](https://github.com/msgpack/msgpack/blob/master/spec.md) using [**BiReader**](https://github.com/hearhellacopters/bireader) to improve storage size and create efficient binary serialization. 

**JamPak** improvements over MessagePack:
 - Reduced file size by spliting data into two sections, **values** and **strings**
 - Keys can be stripped for 'schemas' like control to futher reduce file size and added security
 - Compression / Encryption / CRC check
 - Endianness control

***Note: Only compatible with Node.js.**

## How it works

**JamPak**'s secret is it uses JavaScript's own `Set` feature to create a unique array of all string data in the file to cut down on size. Saving index numbers in place of the strings for repeated use. Great for data with large repeating object arrays or "table like" data where string keys are repeated. The file splits the data into two sections, the value section and the string section. The file can be futher compressed with zlib and even encrpyted as well as an optional CRC32 check.

Here is a breakdown of a sample file struture.

<img src="./img/ExampleFile.svg">

## Synopsis

```typescript
import { JPEncode, JPDecode } from "jampak";

const object = {
  null: null,
  undefined: undefined,
  integer: 1,
  float: Math.PI,
  bigint: 0x100000000000000n,
  string: "Hello, world!",
  array: [10, 20, 30],
  object: { foo: "bar" },
  mapExt: new Map([["key1","data1"],["key2","data2"]]),
  setExt: new Set([50, 60, 70]),
  symbolExt: Symbol("symbol"),
  regexExt: /(regex)/g,
  uint8arrayExt: new Uint8Array([1, 2, 3]),
  dateExt: new Date()
};

const encoder = new JPEncode();

const encoded: Buffer = encoder.encode(object);

const decoder = new JPDecode();

const decoded = decoder.decode(encoded);
```

## Table of Contents

- [How it works](#how-it-works)
- [Synopsis](#synopsis)
- [Table of Contents](#table-of-contents)
- [Install](#install)
- [API](#api)
  - [`new JPEncode(EncoderOptions?)`](#new-jpencodeencoderoptions)
    - [`EncoderOptions`](#encoderoptions)
    - [Class `JPEncode` functions](#class-jpencode-functions)
    - [Class `JPEncode` objects](#class-jpencode-objects)
  - [`new JPDecode(DecoderOptions?)`](#new-jpdecodedecoderoptions)
    - [`DecoderOptions`](#DecoderOptions)
    - [Class `JPDecode` functions](#class-jpdecode-functions)
    - [Class `JPDecode` objects](#class-jpdecode-objects)
- [Extension Types](#extension-types)
  - [ExtensionCodec context](#extensioncodec-context)
- [Advanced Features](#advanced-features)
- [JamPak Specification](#JamPak-specification)
  - [JamPak Mapping Table](#JamPak-mapping-table)
  - [JamPak Extension Table](#JamPak-extension-table)
- [Prerequisites](#prerequisites)
- [Binary template](#binary-template)
- [License](#license)

## Install

This library is published to `npmjs.com` as [jampak](https://www.npmjs.com/package/jampak).

```shell
npm install jampak
```

## API

### `new JPEncode(EncoderOptions?)`

Creates a new `JPEncode` class with set `EncoderOptions`. You can then encode your data with `encoder.encode(data)` into a single JamPak-encoded `Buffer`. It throws errors if `data` is, or includes, a non-serializable object such as a `function` or other types not added to the extensions.

Alternatively you can include a `filePath` string as a second argument and write the file out directly.

For example:

```typescript
import { JPEncode } from "jampak";

const encoder: new JPEncode({encrypt:true, stripEncryptKey:true});

const data = { foo: "bar" };

encoder.encode(data, "./foo.jpk"); // Saves the encrypted Buffer directly to file

const encryptionKey = encoder.encryptionKey; // Key for later decryption.
```

#### `EncoderOptions`

| Name                | Type             | Default                       | Desc |
| ------------------- | ---------------- | ----------------------------- | ---  |
| extensionCodec      | JPExtensionCodec   | `ExtensionCodec.defaultCodec` | User added extension types, see [Extension Types](#extension-types). |
| endian              | string           | "little"                      | Change the endianess of the Buffer writing. |
| encrypt             | boolean          | false                         | If the file should be encrypted. |
| encryptionKey       | number           | undefined                     | If you want to set your own 32 bit key. |
| stripEncryptKey     | boolean          | false                         | If the encryption key is not saved within the file. After encoding  you must save the `encryptionKey` from the class it was created from. |
| CRC32               | boolean          | false                         | Add a CRC32 check to the file (recommanded when encrypting). |
| compress            | boolean          | false                         | Compress the file's data. |
| stripKeys           | boolean          | false                         | Remove all keys from the save file. Must save the `keysArray` from the class it was created from. |

#### Class `JPEncode` functions

Note: Outside of the basic `encode`, these functions should only be used within a user created [Extension Type](#extension-types).

| Functions        | Type                                            | Desc |
| ------------------------- | -------------------------------------------------- | ---  |
| encode(object, filePath?) | `function (uknown, string?) : Buffer`      | The basic function that creates the JamPak Buffer. If a `filePath` is supplied, it writes the file directly out. |
|encodeObject(valueWriter, object, depth?)|`function (BiWriter \| BiWriterStream, Record<string, unknown>, number?): number`| Encodes a `Object` to the passed `BiWriter`'s buffer. Returns the number of bytes written. |
|encodeArray(valueWriter, array, depth?) |`function (BiWriter \| BiWriterStream, Array<unknown>, number?): number`| [Extension](#extension-types) function use only. Encodes a `Array` to the passed `BiWriter`'s buffer. Returns the number of bytes written.|
|encodeString(valueWriter, string, isKey?)|`function (BiWriter \| BiWriterStream, string,  boolean?): number`| [Extension](#extension-types) function use only. Encodes a `string` to the string section of the current file and writes the index to the passed `BiWriter`'s buffer. Returns the number of bytes written to the buffer. |
|encodeNull(valueWriter) |`function ( BiWriter \| BiWriterStream): number`| [Extension](#extension-types) function use only. Encodes a `null` to the passed `BiWriter`'s buffer. Returns the number of bytes written. |
|encodeUndefined(valueWriter) |`function (BiWriter \| BiWriterStream): number`| [Extension](#extension-types) function use only. Encodes a `undefined` to the passed `BiWriter`'s buffer. Returns the number of bytes written.|
|encodeBoolean(valueWriter)|`function (BiWriter \| BiWriterStream): number`| [Extension](#extension-types) function use only. Encodes a `true` or `false` to the passed `BiWriter`'s buffer. Returns the number of bytes written.|
|encodeFinished(valueWriter)|`function (BiWriter \| BiWriterStream): number`| [Extension](#extension-types) function use only. Encodes a "finished" byte to the passed `BiWriter`'s buffer. Will end all looping when the reader hits this byte. Returns the number of bytes written. |
|encodeListEnd(valueWriter)|`function (BiWriter \| BiWriterStream): number`| [Extension](#extension-types) function use only. Encodes a "list end" byte to the passed `BiWriter`'s buffer, useful when pulling loose data and don't want to break the whole loop. Returns the number of bytes written. | 
|encodeNumber(valueWriter, number)|`function (BiWriter \| BiWriterStream, number): number`| [Extension](#extension-types) function use only. Encodes a `number` to the passed `BiWriter`'s buffer. Computes the right byte size base on value.  Returns the number of bytes written.|
|encodeBigInt64(valueWriter, bigint)|`function (BiWriter \| BiWriterStream, bigint): number` | [Extension](#extension-types) function use only. Encodes a `bigint` to the passed `BiWriter`'s buffer. Always written as a 64 bit value.|

#### Class `JPEncode` objects

After `encode` has run.

| Name                      | Type                                       | Desc |
------------------------- | ------------------------------------------ | -------------------------------------------------- |
| encryptionKey             | number                                     | The encryption key used in the file. Must be saved if `stripEncryptKey` was used. |
| keysArray                 | string[]                                   | The keys for the object data. Must be saved if `stripKeys` was used. |
| CRC32Hash | number | The computed CRC32 hash if enabled in options |

### `new JPDecode(DecoderOptions?)`

Creates a new `JPDecode` class with set `DecoderOptions`. You can then decode your data with `decoder.decode(data)` from a single JamPak-encoded `Buffer` and returns the decoded object typed `unknown`. If the type of data passed to decode is a `string` it will assume it is a file path and try to read the file data directly.

For example:

```typescript
import { JPDecode } from "jampak";

const decoder: new JPDecode({encryptionKey: 1234});

const object = decoder.decode('./foo.jpk');

console.log(object);
```

#### `DecoderOptions`

| Name            | Type                | Default                                        | Desc |
| --------------- | ------------------- | ---------------------------------------------- | ---- |
| extensionCodec  | JPExtensionCodec      | `ExtensionCodec.defaultCodec`                  | User added extension types, see [Extension Types](#extension-types). |
| keysArray       | string[]            | []                                             | String array from when `stripKeys` was used during encoding. |
| encryptionKey | number| undefined | 32 bit encryption key for when `stripEncryptKey` was enabled in encoding. |
| enforceBigInt | boolean | false |  Ensures all 64 bit values return as `bigint` |
| makeJSON | boolean | false | Forces the decoder to only return only a valid JSON object. See table below for conversions. |

#### Types to JSON table

Type conversion when using `makeJSON` in the decoder.

| Type                                            | Conversion |
| ------------------------- | -------------------------------------------------- | 
|`undefined`| `"undefined"` string|
|`RegExp`| `{regexSrc: string, regexFlags: string}` object|
|`symbol`|`{symbolGlobal: boolean, symbolKey: string}` object|
|`bigint`|`number` if safe, otherwise `string`|
|`Set`|`Array`|
|`Map`|`Array[]`|

Note: If you create [Extension Types](#extension-types), you must handle the conversion in your decode function.

```typescript
import { JPEncode, JPDecode } from "jampak";

const object = {
  null: null,
  undefined: undefined,
  integer: 1,
  float: Math.PI,
  bigint: 0x100000000000000n,
  string: "Hello, world!",
  array: [10, 20, 30],
  object: { foo: "bar" },
  mapExt: new Map([["key1","data1"],["key2","data2"]]),
  setExt: new Set([50, 60, 70]),
  symbolExt: Symbol("symbol"),
  regexExt: /(regex)/g,
  uint8arrayExt: new Uint8Array([1, 2, 3]),
  dateExt: new Date()
};

const encoder = new JPEncode();

const encoded: Buffer = encoder.encode(object);

const decoder: new JPDecode({makeJSON: true});

const object = decoder.decode(encoded);

console.log(object);
// {
//   null: null,
//   undefined: 'undefined',
//   integer: 1,
//   float: 3.141592653589793,
//   bigint: '72057594037927936',
//   string: 'Hello, world!',
//   array: [ 10, 20, 30 ],
//   object: { foo: 'bar' },
//   mapExt: [ [ 'key1', 'data1' ], [ 'key2', 'data2' ] ],
//   setExt: [ 50, 60, 70 ],
//   symbolExt: { symbolGlobal: false, symbolKey: 'symbol' },
//   regexExt: { regexSrc: '(regex)', regexFlags: 'g' },
//   uint8arrayExt: { '0': 1, '1': 2, '2': 3 },
//   bufferExt: { type: 'Buffer', data: [ 1, 2, 3 ] },
//   dateExt: '2025-07-10T02:17:53.721Z'
// }
```

#### Class `JPDecode` functions

Note: Outside of the basic `decode`, these functions should only be used within a user created [Extension Type](#extension-types).


| Functions        | Type                                            | Desc |
| ------------------------- | -------------------------------------------------- | ---  |
| decode(bufferOrSourcePath)  | `function (Buffer \| string) : unknown` | Your Buffer to decode or the source path to a JamPak file. | The function that decodes the JamPak Buffer. |
| decodeAsync(bufferOrSourcePath)  | `function (Buffer \| string) : Promise<unknown>` | Your Buffer to decode or the source path to a JamPak file. | The function that decodes the JamPak Buffer. |
| doDecodeSync(bufferOrReader)| `function (reader: Buffer \| BiReader \| BiReaderStream): unknown` | [Extension](#extension-types) function use only. Runs a raw decode on the passed `BiReader`'s Buffer. Return data wherever it ends based on the start value. |
|doDecodeAsync(bufferOrReader)| `async function (reader: Buffer \| BiReader \| BiReaderStream): Promise<unknown>` | [Extension](#extension-types) function use only. Runs a raw decode on the passed `Buffer` or `BiReader`. Return data wherever it ends based on the start value. |

#### Class `JPDecode` objects

After `decode` or `decodeAsync` as run.

| Name                      | Type                                       | Desc                                            
| ------------------------- | ------------------------------------------ | -------------------------------------------------- 
| symbolList | symbol[] | Any symbol created on decode are in this array. |
| hasExtensions | boolean | If the returned data had any extension types used. |
| validJSON |`boolean` | If the decoded data can to converted to JSON |
| CRC32OnFile | `number` | The CRC32 hash on file. | 
| CRC32Hash | `number` | The computed CRC32 hash of the file. | 

## Extension Types

To handle Extension Types, this library provides `JPExtensionCodec` class.

This is an example to setup custom extension types that handles `Date` classes in TypeScript:

```typescript
import { BiWriter, BiReader, BiReaderStream } from "bireader";
import { JPDecode, JPEncode, JPExtensionCodec } from "jampak";

// Note this is an example, this extension is built in.

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
 * @param {ContextType} context - Context of the class
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
    // make sure the writer is in the same endian as the encoder
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
 * @param {JPDecode<ContextType>} decoder - class decoder
 * @param {number} extensionType - Registered extension number between 0x00 - 0xCF (for dummy checks)
 * @param {ContextType} context - Context of the class (shouldn't be needed)
 * @returns {Date}
 */
function decodeTimestampExtension<ContextType = undefined>(
  data: BiReader | BiReaderStream,
  decoder: JPDecode<ContextType>,
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

const ExtCodec = new JPExtensionCodec();

ExtCodec.register(timestampExtension);

const encoder = new JPEncode({ extensionCodec: ExtCodec });

const encoded = encoder.encode(new Date());

const decoded = new JPDecode({ extensionCodec: ExtCodec });

const decoded = decoder.decode(encoded);
```

Ensure you include your extensionCodec in any recursive encode and decode statements!

Note that extension types for custom objects must be `0x00 - 0xCF`, while `0xD0 - 0xFF` is reserved for JamPak itself.

### ExtensionCodec context

When you use an extension codec, it might be necessary to have encoding/decoding state to keep track of which objects got encoded/re-created. To do this, pass a `context` to the `EncoderOptions` and `DecoderOptions`:

```typescript
import { BiWriter, BiReader, BiReaderStream } from "bireader";
import { JPDecode, JPEncode, JPExtensionCodec } from "jampak";

class MyContext {
  track(object: any) { /*...*/ }
}

class MyType { /* ... */ }

const ExtCodec = new ExtensionCodec<MyContext>();

// MyType
const MYTYPE_EXT_TYPE = 0 // Any in 0x00 - 0xCF
ExtCodec.register({
  type: MYTYPE_EXT_TYPE,
  encode: (object, encoder, context) => {
    if (object instanceof MyType) {
      context.track(object);
      return encoder.encodeObject(object.toJSON());
    } else {
      return null;
    }
  },
  decode: (data, decoder, extType, context) => {
    const decoded = decoder.doDecodeSync(data);
    const my = new MyType(decoded);
    context.track(my);
    return my;
  },
});

// and later
import { JPDecode, JPEncode } from "jampak";

const context = new MyContext();

const encoder = new JPEncode({ extensionCodec: ExtCodec, context: context });

const encoded = encoder.encode({ myType: new MyType<any>() });

const decoder = new JPEncode({ extensionCodec: ExtCodec, context: context });

const decoded = decoder.decode(encoded);
```

## Advanced Features

**JamPak** has four major features: encryption, compression, key stripping and CRC check.

- `encrypt`
  - Outside of the 32 byte header, all data is encrypted with either a random 32 bit number or one you supplied with `encryptionKey` before encoding. The value is **NOT** the key, but a sead for a RNG that picks one of 3 different encryption setups and generates both the key and the IV. 
  - The encryption value is can be saved to the file (by default) or it can be remove with `stripEncryptKey`. The `encryptionKey` object in the class after encoding **MUST** be saved or the file won't be able to be decrypted.
  - A CRC check is recommended on when using encryption to ensure the data decrypted correctly.
- `compress`
  - Outside of the 32 byte header, the file is compressed in 512kb zlib chunks. You can also encrypt the compressed file as well (encryption happens after compression)
  - The amount of data saved depends on the size of the file and the type of data within.
- `stripKeys`
  - More for security than size savings, this creates a *schema* like file where the keys to the data aren't include in the file. The keys can be found in the `keysArray` object in the class after encoding and **MUST** be saved or the file won't be able to be decrypted.
- `CRC32`
  - Outside of the 32 byte header, runs a CRC32 hash on the values and string data. Saves the hash to the file. Recommended when using either `encrypt` or `compress`.

## JamPak Specification

This library is based around the MessagePack specification (head byte, optional size, then data), but modified and expanded to better fit JavaScript and TypeScript data types. It mindfully encodes data first by JSON standard types (object, array, number, boolean, string, null) then extends into other types:

* [x] Keys separation, for key stripping for extra security.
* [x] Kill byte, so the decoder knowns when the data is finished.
* [x] `bigint` always encodes to 64 bit but will return as a `number` if within safe `number` range.
* [x] `Map` ext type (NOT object)
* [x] `Set` ext type
* [x] `Symbol` ext type
* [x] `TypedArray` ext type (from `BigUint64Array` to `Uint8ClampedArray`)
* [x] `Buffer` ext type
* [x] `Date` ext type

### JamPak Mapping Table

The following table shows how JavaScript values are mapped to JamPak formats.

| Source Value          | Head Byte      | Desc                  |
| --------------------- | ------------------------ | --------------------- |
| number                | 0x00 - 0x7F, 0xE0 - 0xFF | Small values saved directly, same as MessagePack |
| Object                | 0x80 - 0x8F, 0xC7 - 0xC9 | Always as `Record<string, unknown>`      |
| Array                 | 0x90 - 0x9F, 0xDA - 0xDC | Array                 |
| string*               | 0xB0 - 0xBF, 0xD7 - 0xD9 | Strings are saved in their own unique way in the seporate string section of the data. The only data saved in the value section is the index to the string in the string section.   |
| keys*                 | 0xA0 - 0xAF, 0xD4 - 0xD6 | Just like strings above but the data here is just an index to an array that is NOT saved with the file. The object `keysArray` of the `JPEncode` class must be saved and passed back to the `JPDeocde` class or the file won't be readable. |
| null                  | 0xC0                     | null                  |
| undefined*            | 0xC1                     | undefined           |
| boolean (true, false) | 0xC2 or 0xC3             | True or False |
| number (float)        | 0xCA or 0xCB             | Checks if value needs to be saved as 32 or 64 bit               |
| number (8-64-bit int) | 0xCC - 0xD3              | numbers between 8 - 64 bit               |
| bigint*               | 0xCF or 0xD3             | Will always be written as 64 bit but will only return as `bigint` type if outside of safe `number` range or `enforceBigInt` is true in options  |
| Kill byte*            | 0xC4                     | Triggers the end of the data |
| List end*             | 0xC5                     | Can be useful in extension for splitting data without end decoding process like the kill byte |
| Extensions            | 0xDD - 0xDF              | Uses a secondary index for all built in and user added types | 

* *Different to MessagePack

### JamPak Extension Table

The following are built in types that JamPak works with. Users can add their own [Extension Types](#extension-types) with numbers between 0x00 - 0xCF. Note: these types are outside of the basic types JSON data deals with so their storage is specific to JamPak.

| Extension Type                    | Extension Number     | Desc                  |
| --------------------------------- | -------------------- | --------------------- |
| Map                               | 0xEE                 | Just like `Object` but the keys here are expanded. The size value here are the length of the map, not the buffer. |
| Set                               | 0xEF                 | Like an `Array` but with a unique list. The size value here are the size of the set, not the buffer. |
| Symbol                            | 0xF0                 | Has a fixed boolean and string. Any generated symbol can also be found in the array `symbolList` object from the `JPDecode` class. Note: symbols used as keys can't encode as the reason for those use cases is to conceal the data.   |
| RegEx                             | 0xF1                 | Has two strings. Creates `new RegExp()`          |
| `TypedArray`                      | 0xF2 - 0xFD          | `BigUint64Array` to `Uint8ClampedArray `          |
| Buffer                            | 0xFE                 | Node default `Buffer`                |
| Date                              | 0xFF                 | Same function from the example.            |

## Prerequisites

This is a universal JavaScript library that supports only NodeJS. NodeJS v18 is required.

## Binary template

For a full understanding of the file structure, the most up-to-date JAMPAK.bt binary template can be found [here](https://github.com/hearhellacopters/jampak/blob/main/JAMPAK.bt).

## License

This software uses the ISC license:

https://opensource.org/licenses/ISC