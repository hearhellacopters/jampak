'use strict';

var fs = require('fs');
var crypto = require('node:crypto');
var fsp = require('fs/promises');
var zlib = require('zlib');
var node_buffer = require('node:buffer');

// #region Types
// #region Checks
const testFallback = process && process.argv && process.argv.indexOf("FALLBACK=true") != -1;
const canInt8 = testFallback ? false : "getUint8" in DataView.prototype && "getInt8" in DataView.prototype && "setUint8" in DataView.prototype && "setInt8" in DataView.prototype;
const canInt16 = testFallback ? false : "getUint16" in DataView.prototype && "getInt16" in DataView.prototype && "setUint16" in DataView.prototype && "setInt16" in DataView.prototype;
const canFloat16 = testFallback ? false : 'getFloat16' in DataView.prototype && 'setFloat16' in DataView.prototype;
const canInt32 = testFallback ? false : 'getInt32' in DataView.prototype && 'getUint32' in DataView.prototype && 'setInt32' in DataView.prototype && 'setUint32' in DataView.prototype;
const canFloat32 = testFallback ? false : "getFloat32" in DataView.prototype && "setFloat32" in DataView.prototype;
const canBigInt64 = testFallback ? false : "getBigUint64" in DataView.prototype && "getBigInt64" in DataView.prototype && "setBigUint64" in DataView.prototype && "setBigInt64" in DataView.prototype;
const canFloat64 = testFallback ? false : "getFloat64" in DataView.prototype && "setFloat64" in DataView.prototype;
const hasBigInt = typeof BigInt === 'function';
const MIN_SAFE_BIGINT = hasBigInt ? BigInt(Number.MIN_SAFE_INTEGER) : 0;
const MAX_SAFE_BIGINT = hasBigInt ? BigInt(Number.MAX_SAFE_INTEGER) : 0;
// #region Helpers
/**
 * If value can be convert to number
 */
function isSafeInt64(big) {
    return hasBigInt ? (big >= MIN_SAFE_BIGINT && big <= MAX_SAFE_BIGINT) : false;
}
function isBuffer(obj) {
    return (typeof Buffer !== 'undefined' && Buffer.isBuffer(obj));
}
function isUint8Array(obj) {
    if (typeof Buffer === 'undefined') {
        return true;
    }
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(obj)) {
        return false;
    }
    return true;
}
function isBufferOrUint8Array(obj) {
    return obj instanceof Uint8Array || isBuffer(obj);
}
function normalizeBitOffset(bit) {
    return ((bit % 8) + 8) % 8;
}
function safeFromCharCode(arr) {
    const chunk = 0x8000;
    let result = "";
    for (let i = 0; i < arr.length; i += chunk) {
        result += String.fromCharCode(...arr.slice(i, i + chunk));
    }
    return result;
}
function safeFromCodePoint(arr) {
    const chunk = 0x8000;
    let result = "";
    for (let i = 0; i < arr.length; i += chunk) {
        result += String.fromCodePoint(...arr.slice(i, i + chunk));
    }
    return result;
}
function textEncode(string, bytesPerChar = 1) {
    switch (bytesPerChar) {
        case 1:
            return new TextEncoder().encode(string);
        case 2:
            {
                const utf16Buffer = new Uint16Array(string.length);
                for (let i = 0; i < string.length; i++) {
                    utf16Buffer[i] = string.charCodeAt(i);
                }
                return new Uint8Array(utf16Buffer.buffer);
            }
        case 4:
            {
                const utf32Buffer = new Uint32Array(string.length);
                for (let i = 0; i < string.length; i++) {
                    utf32Buffer[i] = string.codePointAt(i);
                }
                return new Uint8Array(utf32Buffer.buffer);
            }
        default:
            return new Uint8Array(0);
    }
}
/**
 * Converts the number to a safe value
 */
function numberSafe(value, bits, unsigned) {
    var min, max;
    if (!!unsigned == true || bits == 1) {
        switch (bits) {
            case 8:
                max = 255;
                break;
            case 16:
                max = 65535;
                break;
            case 32:
                max = 4294967295;
                break;
            default:
                {
                    if (bits <= 54) {
                        max = Math.pow(2, bits) - 1;
                    }
                    else if (bits > 54 && hasBigInt) {
                        max = Math.pow(2, bits) - 1;
                    }
                    else {
                        throw new RangeError("System can't have BigInt support to handle large numbers.");
                    }
                }
                break;
        }
        min = 0;
    }
    else {
        switch (bits) {
            case 8:
                max = 127;
                break;
            case 16:
                max = 32767;
                break;
            case 32:
                max = 2147483647;
                break;
            default:
                {
                    if (bits <= 55) {
                        max = Math.pow(2, bits - 1) - 1;
                    }
                    else if (bits > 55 && hasBigInt) {
                        max = Math.pow(2, bits - 1) - 1;
                    }
                    else {
                        throw new RangeError("System can't have BigInt support to handle large numbers.");
                    }
                }
                break;
        }
        min = -max - 1;
    }
    if (value < min) {
        if (typeof value == "bigint") {
            return BigInt(min);
        }
        else {
            return min;
        }
    }
    else if (value > max) {
        if (typeof value == "bigint") {
            return BigInt(max);
        }
        else {
            return max;
        }
    }
    else {
        return value;
    }
}
function _hexDump(data, options = {}, start, end) {
    function _hexCheck(byte, bits) {
        var value = 0;
        for (var i = 0; i < bits;) {
            const remaining = bits - i;
            const bitOffset = 0;
            const currentByte = byte;
            const read = Math.min(remaining, 8 - bitOffset);
            const mask = ~(0xFF << read);
            const readBits = (currentByte >> (8 - read - bitOffset)) & mask;
            value <<= read;
            value |= readBits;
            i += read;
        }
        value = value >>> 0;
        return value;
    }
    const suppressUnicode = options && options.suppressUnicode || false;
    const rows = [];
    var header = "   0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F  ";
    const ending = "0123456789ABCDEF";
    var addr = "";
    for (let i = start; i < end; i += 16) {
        addr = i.toString(16).padStart(5, '0');
        var row = data.subarray(i, i + 16) || [];
        var hex = Array.from(row, (byte) => byte.toString(16).padStart(2, '0')).join(' ');
        rows.push(`${addr}  ${hex.padEnd(47)}  `);
    }
    let result = '';
    let makeWide = false;
    let i = start;
    while (i < end) {
        const byte = data[i];
        if (byte < 32 || byte == 127) {
            result += '.';
        }
        else if (byte < 127) {
            // Valid UTF-8 start byte or single-byte character
            // Convert the byte to a character and add it to the result
            result += String.fromCharCode(byte);
        }
        else if (suppressUnicode) {
            result += '.';
        }
        else if (_hexCheck(byte, 1) == 0) {
            //Byte 1
            result += String.fromCharCode(byte);
        }
        else if (_hexCheck(byte, 3) == 6) {
            //Byte 2
            if (i + 1 <= end) {
                //check second byte
                const byte2 = data[i + 1];
                if (_hexCheck(byte2, 2) == 2) {
                    const charCode = ((byte & 0x1f) << 6) | (byte2 & 0x3f);
                    i++;
                    makeWide = true;
                    const read = " " + String.fromCharCode(charCode);
                    result += read;
                }
                else {
                    result += ".";
                }
            }
            else {
                result += ".";
            }
        }
        else if (_hexCheck(byte, 4) == 14) {
            //Byte 3
            if (i + 1 <= end) {
                //check second byte
                const byte2 = data[i + 1];
                if (_hexCheck(byte2, 2) == 2) {
                    if (i + 2 <= end) {
                        //check third byte
                        const byte3 = data[i + 2];
                        if (_hexCheck(byte3, 2) == 2) {
                            const charCode = ((byte & 0x0f) << 12) |
                                ((byte2 & 0x3f) << 6) |
                                (byte3 & 0x3f);
                            i += 2;
                            makeWide = true;
                            const read = "  " + String.fromCharCode(charCode);
                            result += read;
                        }
                        else {
                            i++;
                            result += " .";
                        }
                    }
                    else {
                        i++;
                        result += " .";
                    }
                }
                else {
                    result += ".";
                }
            }
            else {
                result += ".";
            }
        }
        else if (_hexCheck(byte, 5) == 28) {
            //Byte 4
            if (i + 1 <= end) {
                //check second byte
                const byte2 = data[i + 1];
                if (_hexCheck(byte2, 2) == 2) {
                    if (i + 2 <= end) {
                        //check third byte
                        const byte3 = data[i + 2];
                        if (_hexCheck(byte3, 2) == 2) {
                            if (i + 3 <= end) {
                                //check fourth byte
                                const byte4 = data[i + 2];
                                if (_hexCheck(byte4, 2) == 2) {
                                    const charCode = (((byte4 & 0xFF) << 24) | ((byte3 & 0xFF) << 16) | ((byte2 & 0xFF) << 8) | (byte & 0xFF));
                                    i += 3;
                                    makeWide = true;
                                    const read = "   " + String.fromCharCode(charCode);
                                    result += read;
                                }
                                else {
                                    i += 2;
                                    result += "  .";
                                }
                            }
                            else {
                                i += 2;
                                result += "  .";
                            }
                        }
                        else {
                            i++;
                            result += " .";
                        }
                    }
                    else {
                        i++;
                        result += " .";
                    }
                }
                else {
                    result += ".";
                }
            }
            else {
                result += ".";
            }
        }
        else {
            // Invalid UTF-8 byte, add a period to the result
            result += '.';
        }
        i++;
    }
    const chunks = result.match(new RegExp(`.{1,${16}}`, 'g'));
    chunks?.forEach((self, i) => {
        rows[i] = rows[i] + (makeWide ? "|" + self + "|" : self);
    });
    header = "".padStart(addr.length) + header + (makeWide ? "" : ending);
    rows.unshift(header);
    if (makeWide) {
        rows.push("*Removed character byte header on unicode detection");
    }
    if (options && options.returnString) {
        return rows.join("\n");
    }
    else {
        const retVal = rows.join("\n");
        console.log(retVal);
        return retVal;
    }
}
// #region Math
function _AND(data, start, end, andKey) {
    if (typeof andKey == "string") {
        andKey = Uint8Array.from(Array.from(andKey).map(letter => letter.charCodeAt(0)));
    }
    if (isBufferOrUint8Array(andKey) || typeof andKey == "number") {
        var index = -1;
        for (let i = start; i < end; i++) {
            if (typeof andKey == "number") {
                data[i] = data[i] & (andKey & 0xff);
            }
            else {
                if (index != andKey.length - 1) {
                    index++;
                }
                else {
                    index = 0;
                }
                data[i] = data[i] & andKey[index];
            }
        }
        return { offset: end, bitoffset: 0 };
    }
    else {
        throw new Error("AND key must be a byte value, string, Uint8Array or Buffer");
    }
}
function _OR(data, start, end, orKey) {
    if (typeof orKey == "string") {
        orKey = Uint8Array.from(Array.from(orKey).map(letter => letter.charCodeAt(0)));
    }
    if (isBufferOrUint8Array(orKey) || typeof orKey == "number") {
        var index = -1;
        for (let i = start; i < end; i++) {
            if (typeof orKey == "number") {
                data[i] = data[i] | (orKey & 0xff);
            }
            else {
                if (index != orKey.length - 1) {
                    index++;
                }
                else {
                    index = 0;
                }
                data[i] = data[i] | orKey[index];
            }
        }
        return { offset: end, bitoffset: 0 };
    }
    else {
        throw new Error("OR key must be a byte value, string, Uint8Array or Buffer");
    }
}
function _XOR(data, start, end, xorKey) {
    if (typeof xorKey == "string") {
        xorKey = Uint8Array.from(Array.from(xorKey).map(letter => letter.charCodeAt(0)));
    }
    if (isBufferOrUint8Array(xorKey) || typeof xorKey == "number") {
        let index = -1;
        for (let i = start; i < end; i++) {
            if (typeof xorKey == "number") {
                data[i] = data[i] ^ (xorKey & 0xff);
            }
            else {
                if (index != xorKey.length - 1) {
                    index++;
                }
                else {
                    index = 0;
                }
                data[i] = data[i] ^ xorKey[index];
            }
        }
        return { offset: end, bitoffset: 0 };
    }
    else {
        throw new Error("XOR key must be a byte value, string, Uint8Array or Buffer");
    }
}
function _LSHIFT(data, start, end, shiftKey) {
    if (typeof shiftKey == "string") {
        shiftKey = Uint8Array.from(Array.from(shiftKey).map(letter => letter.charCodeAt(0)));
    }
    if (isBufferOrUint8Array(shiftKey) || typeof shiftKey == "number") {
        var index = -1;
        for (let i = start; i < end; i++) {
            if (typeof shiftKey == "number") {
                data[i] = data[i] << shiftKey;
            }
            else {
                if (index != shiftKey.length - 1) {
                    index++;
                }
                else {
                    index = 0;
                }
                data[i] = data[i] << shiftKey[index];
            }
        }
        return { offset: end, bitoffset: 0 };
    }
    else {
        throw new Error("Left Shift key must be a byte value, string, Uint8Array or Buffer");
    }
}
function _RSHIFT(data, start, end, shiftKey) {
    if (typeof shiftKey == "string") {
        shiftKey = Uint8Array.from(Array.from(shiftKey).map(letter => letter.charCodeAt(0)));
    }
    if (isBufferOrUint8Array(shiftKey) || typeof shiftKey == "number") {
        var index = -1;
        for (let i = start; i < end; i++) {
            if (typeof shiftKey == "number") {
                data[i] = data[i] >> shiftKey;
            }
            else {
                if (index != shiftKey.length - 1) {
                    index++;
                }
                else {
                    index = 0;
                }
                data[i] = data[i] >> shiftKey[index];
            }
        }
        return { offset: end, bitoffset: 0 };
    }
    else {
        throw new Error("Right Shift key must be a byte value, string, Uint8Array or Buffer");
    }
}
function _ADD(data, start, end, addKey) {
    if (typeof addKey == "string") {
        addKey = Uint8Array.from(Array.from(addKey).map(letter => letter.charCodeAt(0)));
    }
    if (isBufferOrUint8Array(addKey) || typeof addKey == "number") {
        var index = -1;
        for (let i = start; i < end; i++) {
            if (typeof addKey == "number") {
                data[i] = data[i] + addKey;
            }
            else {
                if (index != addKey.length - 1) {
                    index = index + 1;
                }
                else {
                    index = 0;
                }
                data[i] = data[i] + addKey[index];
            }
        }
        return { offset: end, bitoffset: 0 };
    }
    else {
        throw new Error("ADD key must be a byte value, string, Uint8Array or Buffer");
    }
}
function _NOT(data, start, end) {
    for (let i = start; i < end; i++) {
        data[i] = ~data[i];
    }
    return { offset: end, bitoffset: 0 };
}
// #region Read / Writes
/**
 * bit read function
 */
function _rbit(data, bits, offset, endian, unsigned) {
    var value = 0;
    for (var i = 0; i < bits;) {
        const remaining = bits - i;
        const bitOffset = offset & 7;
        const currentByte = data[offset >> 3];
        const read = Math.min(remaining, 8 - bitOffset);
        if (endian == "big") {
            let mask = ~(0xFF << read);
            let readBits = (currentByte >> (8 - read - bitOffset)) & mask;
            value <<= read;
            value |= readBits;
        }
        else {
            let mask = ~(0xFF << read);
            let readBits = (currentByte >> bitOffset) & mask;
            value |= readBits << i;
        }
        offset += read;
        i += read;
    }
    if (!unsigned) {
        const signBit = 1 << (bits - 1);
        if (value & signBit) {
            value -= (1 << bits);
        }
    }
    return value;
}
/**
 * Write bits
 */
function _wbit(data, value, bits, offsetBit, endian, unsigned) {
    // fits the value as unsigned
    if (unsigned == true || bits == 1) {
        const maxValue = Math.pow(2, bits) - 1;
        value = value & maxValue;
    }
    for (var i = 0; i < bits;) {
        const remaining = bits - i;
        const bitOffset = offsetBit & 7;
        const byteOffset = offsetBit >> 3;
        const written = Math.min(remaining, 8 - bitOffset);
        if (endian == "big") {
            let mask = ~(-1 << written);
            let writeBits = (value >> (bits - i - written)) & mask;
            var destShift = 8 - bitOffset - written;
            let destMask = ~(mask << destShift);
            data[byteOffset] = (data[byteOffset] & destMask) | (writeBits << destShift);
        }
        else {
            let mask = ~(0xFF << written);
            let writeBits = value & mask;
            value >>= written;
            let destMask = ~(mask << bitOffset);
            data[byteOffset] = (data[byteOffset] & destMask) | (writeBits << bitOffset);
        }
        offsetBit += written;
        i += written;
    }
    return;
}
function _rbyte(data, offset, unsigned) {
    const value = data[offset];
    if (unsigned == true) {
        return value & 0xFF;
    }
    else {
        return value > 127 ? value - 256 : value;
    }
}
function _wbyte(data, value, offset, unsigned) {
    data[offset] = unsigned ? value & 0xFF : value;
    return;
}
function _rint16(data, offset, endian, unsigned) {
    var value;
    if (endian == "little") {
        value = ((data[offset + 1] & 0xFFFF) << 8) | (data[offset] & 0xFFFF);
    }
    else {
        value = ((data[offset] & 0xFFFF) << 8) | (data[offset + 1] & 0xFFFF);
    }
    if (!!unsigned == false) {
        const signBit = 1 << (16 - 1);
        if (value & signBit) {
            value -= (1 << 16);
        }
    }
    return value;
}
function _wint16(data, value, offset, endian, unsigned = false) {
    if (endian == "little") {
        data[offset] = unsigned == false ? value : value & 0xff;
        data[offset + 1] = unsigned == false ? (value >> 8) : (value >> 8) & 0xff;
    }
    else {
        data[offset] = unsigned == false ? (value >> 8) : (value >> 8) & 0xff;
        data[offset + 1] = unsigned == false ? value : value & 0xff;
    }
    return;
}
function _rhalffloat(data, offset, endian) {
    const value = _rint16(data, offset, endian, true);
    const sign = (value & 0x8000) >> 15;
    const exponent = (value & 0x7C00) >> 10;
    const fraction = value & 0x03FF;
    var floatValue;
    if (exponent === 0) {
        if (fraction === 0) {
            floatValue = (sign === 0) ? 0 : -0; // +/-0
        }
        else {
            // Denormalized number
            floatValue = (sign === 0 ? 1 : -1) * Math.pow(2, -14) * (fraction / 0x0400);
        }
    }
    else if (exponent === 0x1F) {
        if (fraction === 0) {
            floatValue = (sign === 0) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
        }
        else {
            floatValue = Number.NaN;
        }
    }
    else {
        // Normalized number
        floatValue = (sign === 0 ? 1 : -1) * Math.pow(2, exponent - 15) * (1 + fraction / 0x0400);
    }
    return floatValue;
}
const float32Array = new Float32Array(1);
const float32AsInts = new Uint32Array(float32Array.buffer);
function _whalffloat(data, value, offset, endian) {
    float32Array[0] = value;
    const x = float32AsInts[0];
    const sign = (x >> 31) & 0x1;
    var exponent = (x >> 23) & 0xff;
    var mantissa = x & 0x7fffff;
    var halfFloatBits;
    if (exponent === 0xff) {
        // NaN or Infinity
        halfFloatBits = (sign << 15) | (0x1f << 10) | (mantissa ? 0x200 : 0);
    }
    else if (exponent > 142) {
        // Overflow → Infinity
        halfFloatBits = (sign << 15) | (0x1f << 10);
    }
    else if (exponent < 113) {
        // Subnormal or zero
        if (exponent < 103) {
            halfFloatBits = sign << 15;
        }
        else {
            mantissa |= 0x800000;
            const shift = 125 - exponent;
            mantissa = mantissa >> shift;
            halfFloatBits = (sign << 15) | (mantissa >> 13);
        }
    }
    else {
        // Normalized
        exponent = exponent - 112;
        mantissa = mantissa >> 13;
        halfFloatBits = (sign << 15) | (exponent << 10) | mantissa;
    }
    if (endian == "little") {
        data[offset] = halfFloatBits & 0xFF;
        data[offset + 1] = (halfFloatBits >> 8) & 0xFF;
    }
    else {
        data[offset] = (halfFloatBits >> 8) & 0xFF;
        data[offset + 1] = halfFloatBits & 0xFF;
    }
    return;
}
function _rint32(data, offset, endian, unsigned) {
    var value;
    if (endian == "little") {
        value = ((data[offset + 3] & 0xFF) << 24) |
            ((data[offset + 2] & 0xFF) << 16) |
            ((data[offset + 1] & 0xFF) << 8) |
            (data[offset] & 0xFF);
    }
    else {
        value = ((data[offset] & 0xFF) << 24) |
            ((data[offset + 1] & 0xFF) << 16) |
            ((data[offset + 2] & 0xFF) << 8) |
            (data[offset + 3] & 0xFF);
    }
    if (unsigned) {
        return value >>> 0;
    }
    return value;
}
function _wint32(data, value, offset, endian, unsigned = false) {
    if (endian == "little") {
        data[offset] = unsigned == false ? value : value & 0xFF;
        data[offset + 1] = unsigned == false ? (value >> 8) : (value >> 8) & 0xFF;
        data[offset + 2] = unsigned == false ? (value >> 16) : (value >> 16) & 0xFF;
        data[offset + 3] = unsigned == false ? (value >> 24) : (value >> 24) & 0xFF;
    }
    else {
        data[offset] = unsigned == false ? (value >> 24) : (value >> 24) & 0xFF;
        data[offset + 1] = unsigned == false ? (value >> 16) : (value >> 16) & 0xFF;
        data[offset + 2] = unsigned == false ? (value >> 8) : (value >> 8) & 0xFF;
        data[offset + 3] = unsigned == false ? value : value & 0xFF;
    }
    return;
}
function _rfloat(data, offset, endian) {
    const uint32Value = _rint32(data, offset, endian, true);
    const isNegative = (uint32Value & 0x80000000) !== 0 ? 1 : 0;
    // Extract the exponent and fraction parts
    const exponent = (uint32Value >> 23) & 0xFF;
    const fraction = uint32Value & 0x7FFFFF;
    // Calculate the float value
    var floatValue;
    if (exponent === 0) {
        // Denormalized number (exponent is 0)
        floatValue = Math.pow(-1, isNegative) * Math.pow(2, -126) * (fraction / Math.pow(2, 23));
    }
    else if (exponent === 0xFF) {
        // Infinity or NaN (exponent is 255)
        floatValue = fraction === 0 ? (isNegative ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY) : Number.NaN;
    }
    else {
        // Normalized number
        floatValue = Math.pow(-1, isNegative) * Math.pow(2, exponent - 127) * (1 + fraction / Math.pow(2, 23));
    }
    return floatValue;
}
function _wfloat(data, value, offset, endian) {
    float32Array[0] = value;
    _wint32(data, float32AsInts[0], offset, endian, true);
    return;
}
function _rint64(data, offset, endian, unsigned) {
    var value = BigInt(0);
    for (let i = 0; i < 8; i++) {
        if (endian == "little") {
            value = value | BigInt((data[offset + i] & 0xFF)) << BigInt(8 * i);
        }
        else {
            value = (value << BigInt(8)) | BigInt((data[offset + i] & 0xFF));
        }
    }
    if (unsigned == false) {
        if (value & (BigInt(1) << BigInt(63))) {
            value -= BigInt(1) << BigInt(64);
        }
    }
    return value;
}
function _wint64(data, value, offset, endian, unsigned) {
    const bigIntArray = unsigned ? new BigUint64Array(1) : new BigInt64Array(1);
    bigIntArray[0] = BigInt(value);
    // Use two 32-bit views to write the Int64
    const int32Array = unsigned ? new Uint32Array(bigIntArray.buffer) : new Int32Array(bigIntArray.buffer);
    for (let i = 0; i < 2; i++) {
        _wint32(data, int32Array[i], offset + (i * 4), endian, unsigned);
    }
    return;
}
function _rdfloat(data, offset, endian) {
    var uint64Value = _rint64(data, offset, endian, true);
    const sign = (BigInt(uint64Value) & BigInt("9223372036854775808")) >> BigInt(63);
    const exponent = Number((BigInt(uint64Value) & BigInt("9218868437227405312")) >> BigInt(52)) - 1023;
    const fraction = Number(BigInt(uint64Value) & BigInt("4503599627370495")) / Math.pow(2, 52);
    var floatValue;
    if (exponent == -1023) {
        if (fraction == 0) {
            floatValue = (sign == BigInt(0)) ? 0 : -0; // +/-0
        }
        else {
            // Denormalized number
            floatValue = (sign == BigInt(0) ? 1 : -1) * Math.pow(2, -1022) * fraction;
        }
    }
    else if (exponent == 1024) {
        if (fraction == 0) {
            floatValue = (sign == BigInt(0)) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
        }
        else {
            floatValue = Number.NaN;
        }
    }
    else {
        // Normalized number
        floatValue = (sign == BigInt(0) ? 1 : -1) * Math.pow(2, exponent) * (1 + fraction);
    }
    return floatValue;
}
function _wdfloat(data, value, offset, endian) {
    const intArray = new Int32Array(2);
    const floatArray = new Float64Array(intArray.buffer);
    floatArray[0] = value;
    const bytes = new Uint8Array(intArray.buffer);
    for (let i = 0; i < 8; i++) {
        if (endian == "little") {
            data[offset + i] = bytes[i];
        }
        else {
            data[offset + (7 - i)] = bytes[i];
        }
    }
    return;
}
function _rstring(stringType, lengthReadSize, readLengthinBytes, terminateValue, stripNull, encoding, endian, readUByte, readUInt16, readUInt32) {
    const encodedBytes = [];
    if (stringType === 'pascal' || stringType === 'wide-pascal' || stringType === "double-wide-pascal") {
        terminateValue = undefined;
        if (lengthReadSize == 1) {
            readLengthinBytes = readUByte();
        }
        else if (lengthReadSize == 2) {
            readLengthinBytes = readUInt16(endian);
        }
        else if (lengthReadSize == 4) {
            readLengthinBytes = readUInt32(endian);
        }
    }
    var readSize = 1;
    switch (stringType) {
        case 'utf-8':
        case 'ascii':
        case 'pascal':
            readSize = 1;
            break;
        case 'utf-16':
        case 'wide-pascal':
            readSize = 2;
            break;
        case 'utf-32':
        case 'double-wide-pascal':
            readSize = 4;
            break;
    }
    for (let i = 0; i < readLengthinBytes; i++) {
        var read = terminateValue;
        switch (readSize) {
            case 1:
                read = readUByte();
                break;
            case 2:
                read = readUInt16(endian);
                i++;
                break;
            case 4:
                read = readUInt32(endian);
                i++;
                i++;
                i++;
                if (stringType == 'utf-32' && read > 0x10FFFF) {
                    read = terminateValue;
                }
                break;
        }
        if (read == terminateValue) {
            break;
        }
        else {
            if (!(stripNull == true && read == 0)) {
                encodedBytes.push(read);
            }
        }
    }
    switch (stringType) {
        case "pascal":
        case "ascii":
        case "utf-16":
        case "wide-pascal":
            return safeFromCharCode(encodedBytes);
        case "double-wide-pascal":
        case "utf-32":
            return safeFromCodePoint(encodedBytes);
        default:
            try {
                return new TextDecoder(encoding).decode(new Uint8Array(encodedBytes));
            }
            catch (err) {
                throw new Error(`Unsupported encoding: ${encoding}`);
            }
    }
}
async function _rstringAsync(stringType, lengthReadSize, readLengthinBytes, terminateValue, stripNull, encoding, endian, readUByte, readUInt16, readUInt32) {
    const encodedBytes = [];
    if (stringType === 'pascal' || stringType === 'wide-pascal' || stringType === "double-wide-pascal") {
        terminateValue = undefined;
        if (lengthReadSize == 1) {
            readLengthinBytes = await readUByte();
        }
        else if (lengthReadSize == 2) {
            readLengthinBytes = await readUInt16(endian);
        }
        else if (lengthReadSize == 4) {
            readLengthinBytes = await readUInt32(endian);
        }
    }
    var readSize = 1;
    switch (stringType) {
        case 'utf-8':
        case 'ascii':
        case 'pascal':
            readSize = 1;
            break;
        case 'utf-16':
        case 'wide-pascal':
            readSize = 2;
            break;
        case 'utf-32':
        case 'double-wide-pascal':
            readSize = 4;
            break;
    }
    for (let i = 0; i < readLengthinBytes; i++) {
        var read = terminateValue;
        switch (readSize) {
            case 1:
                read = await readUByte();
                break;
            case 2:
                read = await readUInt16(endian);
                i++;
                break;
            case 4:
                read = await readUInt32(endian);
                i++;
                i++;
                i++;
                if (stringType == 'utf-32' && read > 0x10FFFF) {
                    read = terminateValue;
                }
                break;
        }
        if (read == terminateValue) {
            break;
        }
        else {
            if (!(stripNull == true && read == 0)) {
                encodedBytes.push(read);
            }
        }
    }
    switch (stringType) {
        case "pascal":
        case "ascii":
        case "utf-16":
        case "wide-pascal":
            return safeFromCharCode(encodedBytes);
        case "double-wide-pascal":
        case "utf-32":
            return safeFromCodePoint(encodedBytes);
        default:
            try {
                return new TextDecoder(encoding).decode(new Uint8Array(encodedBytes));
            }
            catch (err) {
                throw new Error(`Unsupported encoding: ${encoding}`);
            }
    }
}
function _wstring(encodedString, stringType, endian, terminateValue, lengthWriteSize, writeUByte, writeUInt16, writeUInt32) {
    if (stringType == "pascal" ||
        stringType == 'wide-pascal' ||
        stringType == 'double-wide-pascal') {
        if (lengthWriteSize == 1) {
            writeUByte(encodedString.byteLength);
        }
        else if (lengthWriteSize == 2) {
            writeUInt16(encodedString.byteLength, endian);
        }
        else if (lengthWriteSize == 4) {
            writeUInt32(encodedString.byteLength, endian);
        }
    }
    const view = new DataView(encodedString.buffer, encodedString.byteOffset, encodedString.byteLength);
    for (let i = 0; i < view.byteLength; i++) {
        switch (stringType) {
            case 'ascii':
            case 'utf-8':
            case 'pascal':
                writeUByte(view.getUint8(i));
                break;
            case 'utf-16':
            case 'wide-pascal':
                writeUInt16(view.getUint16(i, true), endian);
                i++;
                break;
            case 'utf-32':
            case 'double-wide-pascal':
                writeUInt32(view.getUint32(i, true), endian);
                i++;
                i++;
                i++;
                break;
        }
    }
    if (terminateValue != undefined) {
        if (stringType == "ascii" || stringType == 'utf-8') {
            writeUByte(terminateValue);
        }
        else if (stringType == 'utf-16') {
            writeUInt16(terminateValue, endian);
        }
        else if (stringType == 'utf-32') {
            writeUInt32(terminateValue, endian);
        }
    }
}
async function _wstringAsync(encodedString, stringType, endian, terminateValue, lengthWriteSize, writeUByte, writeUInt16, writeUInt32) {
    if (stringType == "pascal" ||
        stringType == 'wide-pascal' ||
        stringType == 'double-wide-pascal') {
        if (lengthWriteSize == 1) {
            await writeUByte(encodedString.byteLength);
        }
        else if (lengthWriteSize == 2) {
            await writeUInt16(encodedString.byteLength, endian);
        }
        else if (lengthWriteSize == 4) {
            await writeUInt32(encodedString.byteLength, endian);
        }
    }
    const view = new DataView(encodedString.buffer, encodedString.byteOffset, encodedString.byteLength);
    for (let i = 0; i < view.byteLength; i++) {
        switch (stringType) {
            case 'ascii':
            case 'utf-8':
            case 'pascal':
                await writeUByte(view.getUint8(i));
                break;
            case 'utf-16':
            case 'wide-pascal':
                await writeUInt16(view.getUint16(i, true), endian);
                i++;
                break;
            case 'utf-32':
            case 'double-wide-pascal':
                await writeUInt32(view.getUint32(i, true), endian);
                i++;
                i++;
                i++;
                break;
        }
    }
    if (terminateValue != undefined) {
        if (stringType == "ascii" || stringType == 'utf-8') {
            await writeUByte(terminateValue);
        }
        else if (stringType == 'utf-16') {
            await writeUInt16(terminateValue, endian);
        }
        else if (stringType == 'utf-32') {
            await writeUInt32(terminateValue, endian);
        }
    }
}

/**
 * @file BiReader / Writer base for working in sync Buffers or full file reads. Node and Browser.
 */
var _a$1;
// #region Class
/**
 * Base class for BiReader and BiWriter
 */
class BiBase {
    /**
     * File System
     */
    static fs;
    /**
     * Endianness of default read.
     * @type {endian}
     */
    endian = "little";
    /**
     * Current read byte location.
     */
    #offset = 0;
    /**
     * Current read byte's bit location. 0 - 7
     */
    #insetBit = 0;
    /**
     * Size in bytes of the current buffer.
     */
    size = 0;
    /**
     * Size in bits of the current buffer.
     */
    bitSize = 0;
    /**
     * Stops the buffer extending on reading or writing outside of current size
     */
    strict = false;
    /**
     * Console log a hexdump on error.
     */
    errorDump = false;
    /**
     * Master Buffer
     */
    #data = null;
    /**
     * DataView of master Buffer
     */
    #view;
    /**
     * When the data buffer needs to be extended while strict mode is ``false``, this will be the amount it extends.
     *
     * Otherwise it extends just the amount of the next written value.
     *
     * This can greatly speed up data writes when large files are being written.
     *
     * NOTE: Using ``BiWriter.get`` or ``BiWriter.return`` will now remove all data after the current write position. Use ``BiWriter.data`` to get the full buffer instead.
     */
    growthIncrement = 1048576;
    /**
     * Open file description
     */
    fd = null;
    /**
     * Current file path
     */
    filePath = null;
    /**
     * File write mode
     */
    fsMode = "r";
    /**
     * The settings that used when using the .str getter / setter
     */
    strDefaults = { stringType: "utf-8", terminateValue: 0x0 };
    /**
     * All int64 reads will return as bigint type
     */
    enforceBigInt;
    /**
     * Not using a file reader.
     */
    isMemoryMode;
    /**
     * If data can not be written to the buffer.
     */
    readOnly;
    /**
     * Get the current buffer data.
     *
     * @type {ReturnMapping<DataType>}
     */
    get data() {
        return this.#data;
    }
    ;
    /**
     * Get the current buffer data.
     *
     * For use in file mode!
     */
    getData() {
        return this.get();
    }
    ;
    /**
     * Set the current buffer data.
     *
     * @param {DataType} data
     */
    set data(data) {
        if (this.isBufferOrUint8Array(data)) {
            this.#data = data;
            this.#updateView();
            this.size = this.#data.length;
            this.bitSize = this.size * 8;
        }
    }
    ;
    wasExpanded = false;
    /**
     * Get the DataView of current buffer data.
     */
    get view() {
        return this.#view;
    }
    ;
    constructor(input, options = {}) {
        const { byteOffset, bitOffset, endianness, strict, growthIncrement, enforceBigInt, readOnly } = options;
        if (typeof strict != "boolean") {
            throw new Error("Strict mode must be true or false");
        }
        this.readOnly = !!readOnly;
        this.strict = readOnly ? true : strict;
        this.fsMode = this.readOnly ? 'r' : 'r+';
        this.enforceBigInt = !!enforceBigInt;
        if (!hasBigInt) {
            this.enforceBigInt = false;
        }
        this.growthIncrement = growthIncrement;
        if (typeof endianness != "string" || !(endianness == "big" || endianness == "little")) {
            throw new TypeError("Endian must be big or little");
        }
        this.endian = endianness;
        if (typeof input == "string") {
            if (typeof Buffer === 'undefined' || typeof _a$1.fs === "undefined") {
                throw new Error(`Can't load file outside of Node. Buffer = ${Buffer}, fs = ${_a$1.fs}.`);
            }
            this.filePath = input;
            this.isMemoryMode = false;
        }
        else if (this.isBufferOrUint8Array(input)) {
            this.data = input;
            this.isMemoryMode = true;
            this.size = this.#data.length;
            this.bitSize = this.#data.length * 8;
        }
        else {
            throw new Error("Write data must be Uint8Array or Buffer");
        }
        this.#offset = byteOffset ?? 0;
        if ((bitOffset ?? 0) != 0) {
            this.#offset = Math.floor(byteOffset / 8);
            this.#insetBit = byteOffset % 8;
        }
        this.#offset = ((Math.abs(this.#offset)) + Math.ceil((Math.abs(this.#insetBit)) / 8));
        // Adjust byte offset based on bit overflow
        this.#offset += Math.floor((Math.abs(this.#insetBit)) / 8);
        // Adjust bit offset
        this.#insetBit = Math.abs(normalizeBitOffset(this.#insetBit)) % 8;
        // Ensure bit offset stays between 0-7
        this.#insetBit = Math.min(Math.max(this.#insetBit, 0), 7);
        // Ensure offset doesn't go negative
        this.#offset = Math.max(this.#offset, 0);
        this.#confrimSize(this.#offset);
    }
    ;
    /**
     * Settings for when using .str
     *
     * @param {stringOptions} settings options to use with .str
     */
    set strSettings(settings) {
        this.strDefaults.encoding = settings.encoding;
        this.strDefaults.endian = settings.endian;
        this.strDefaults.length = settings.length;
        this.strDefaults.lengthReadSize = settings.lengthReadSize;
        this.strDefaults.lengthWriteSize = settings.lengthWriteSize;
        this.strDefaults.stringType = settings.stringType;
        this.strDefaults.stripNull = settings.stripNull;
        this.strDefaults.terminateValue = settings.terminateValue;
    }
    ;
    ///////////////////////////////
    // #region INTERNALS
    ///////////////////////////////
    /**
     * Checks if obj is an Uint8Array or a Buffer
     */
    isBufferOrUint8Array(obj) {
        return isBufferOrUint8Array(obj);
    }
    ;
    /**
     * Checks if obj is a Buffer
     */
    isBuffer(obj) {
        return isBuffer(obj);
    }
    ;
    /**
     * Checks if obj is an Uint8Array
     */
    isUint8Array(obj) {
        return isUint8Array(obj);
    }
    /**
     * Checks if file exists
     *
     * @param {string} filePath
     * @returns
     */
    #fileExists(filePath) {
        if (_a$1.fs == undefined) {
            return false;
        }
        try {
            _a$1.fs.accessSync(filePath, _a$1.fs.constants.F_OK);
            return true; // File exists
        }
        catch (error) {
            // @ts-ignore
            return false;
        }
    }
    ;
    /**
     * Internal update size
     *
     * run after setting data
     */
    #updateSize() {
        if (this.isMemoryMode) {
            this.size = this.#data.length;
            this.bitSize = this.size * 8;
            return;
        }
        if (typeof _a$1.fs === "undefined") {
            throw new Error("Can't load file outside of Node.");
        }
        if (this.fd != null) {
            try {
                const stat = _a$1.fs.fstatSync(this.fd);
                this.size = stat.size;
                this.bitSize = this.size * 8;
            }
            catch (error) {
                throw new Error(error);
            }
        }
    }
    ;
    /**
     * Internal update buffer.
     *
     * Should come after updateSize
     */
    #updateBuffer() {
        if (!this.isMemoryMode) {
            if (this.fd == null) {
                try {
                    this.fd = _a$1.fs.openSync(this.filePath, this.fsMode);
                }
                catch (error) {
                    throw new Error(error);
                }
            }
            const data = Buffer.alloc(this.size);
            try {
                const bytesRead = _a$1.fs.readSync(this.fd, data, 0, data.length, 0);
                if (bytesRead != this.size) {
                    throw new Error("Didn't update file buffer size. Expecting " + this.size + " but got " + bytesRead);
                }
            }
            catch (error) {
                throw new Error(error);
            }
            this.data = data;
            this.#updateSize();
        }
        this.#offset = this.#offset ?? 0;
        this.#insetBit = this.#insetBit ?? 0;
        this.#offset = ((Math.abs(this.#offset)) + Math.ceil((Math.abs(this.#insetBit)) / 8));
        // Adjust byte offset based on bit overflow
        this.#offset += Math.floor((Math.abs(this.#insetBit)) / 8);
        // Adjust bit offset
        this.#insetBit = Math.abs(normalizeBitOffset(this.#insetBit)) % 8;
        // Ensure bit offset stays between 0-7
        this.#insetBit = Math.min(Math.max(this.#insetBit, 0), 7);
        // Ensure offset doesn't go negative
        this.#offset = Math.max(this.#offset, 0);
        this.#confrimSize(this.#offset);
    }
    ;
    /**
     * Call this after everytime we set/replace `this.data`
     */
    #updateView() {
        if (this.#data) {
            this.#view = new DataView(this.#data.buffer, this.#data.byteOffset ?? 0, this.#data.byteLength);
        }
    }
    ;
    /**
     * Calls to check if expanding the buffer needs to happen
     */
    #checkSize(writeBytes = 0, writeBit = 0, offset = this.#offset) {
        this.open();
        const bits = writeBit + this.#insetBit;
        if (bits != 0) {
            //add bits
            writeBytes += Math.ceil(bits / 8);
        }
        //if bigger extend
        this.#confrimSize(offset + writeBytes);
        //start read location
        return offset;
    }
    ;
    /**
     * Checks if input requires expanding the buffer
     */
    #confrimSize(neededSize) {
        if (neededSize <= this.size) {
            return;
        }
        var targetSize = neededSize;
        if (targetSize > this.size) {
            if (this.strict || this.readOnly) {
                this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
                throw new Error(`\x1b[33m[Strict mode]\x1b[0m: Reached end of data: ` + neededSize + " at " + this.#offset + " of " + this.size);
            }
            if (this.growthIncrement != 0) {
                this.wasExpanded = true;
                targetSize = Math.ceil(neededSize / this.growthIncrement) * this.growthIncrement;
            }
            this.#extendArray(targetSize);
        }
    }
    ;
    /**
     * Expends the buffer
     */
    #extendArray(targetSize) {
        this.open();
        if (targetSize <= this.size) {
            return;
        }
        const toPadd = targetSize - this.size;
        if (this.isBuffer(this.#data)) {
            var paddbuffer = Buffer.alloc(toPadd);
            this.data = Buffer.concat([this.#data, paddbuffer]);
        }
        else {
            const newBuf = new Uint8Array(this.size + toPadd);
            newBuf.set(this.#data);
            this.data = newBuf;
        }
        this.size = this.#data.length;
        this.bitSize = this.#data.length * 8;
        return;
    }
    ;
    ///////////////////////////////
    // #region FILE MODE
    ///////////////////////////////
    /**
     * Enables writing and expanding (changes strict AND readonly)
     *
     * @param {boolean} mode - True to enable writing and expanding (changes strict AND readonly)
     */
    writeMode(mode = true) {
        if (mode) {
            this.strict = false;
            this.readOnly = false;
            this.fsMode = "r+";
        }
        else {
            this.strict = true;
            this.readOnly = true;
            this.fsMode = "r";
        }
        if (!this.isMemoryMode) {
            this.close();
            this.open();
        }
    }
    ;
    /**
     * Opens the file in `file` mode. Must be run before reading or writing.
     *
     * Can be used to pass new data to a loaded class, shifting to memory mode.
     */
    open(data) {
        if (this.isBufferOrUint8Array(data)) {
            this.close();
            this.filePath = null;
            this.fd == null;
            this.isMemoryMode = true;
            this.data = data;
            this.#updateSize();
            this.#updateBuffer();
            return;
        }
        if (this.isMemoryMode) {
            return;
        }
        if (this.fd != null) {
            return;
        }
        if (typeof _a$1.fs === "undefined") {
            throw new Error("Can't load file outside of Node.");
        }
        if (!this.#fileExists(this.filePath)) {
            _a$1.fs.writeFileSync(this.filePath, "");
        }
        try {
            this.fd = _a$1.fs.openSync(this.filePath, this.fsMode);
        }
        catch (error) {
            throw new Error(error);
        }
        this.#updateSize();
        this.#updateBuffer();
    }
    ;
    /**
     * commit data and removes it.
     */
    close() {
        if (this.isMemoryMode) {
            const data = this.#data;
            this.#data = null;
            this.#view = null;
            return data;
        }
        if (this.fd === null) {
            return; // Already closed / or not open
        }
        if (typeof _a$1.fs === "undefined") {
            throw new Error("Can't load file outside of Node.");
        }
        this.commit();
        try {
            _a$1.fs.closeSync(this.fd);
        }
        catch (error) {
            throw new Error(error);
        }
        this.fd = null;
        const data = this.#data;
        this.#data = null;
        this.#view = null;
        return data;
    }
    ;
    /**
     * Write data buffer back to file
     */
    commit() {
        if (this.isMemoryMode || this.readOnly) {
            return this.#data;
        }
        // this.mode == "file"
        this.open();
        try {
            _a$1.fs.writeSync(this.fd, this.#data, 0, this.#data.length, 0);
            _a$1.fs.ftruncateSync(this.fd, this.#data.length);
        }
        catch (error) {
            throw new Error(error);
        }
        this.#updateSize();
    }
    ;
    /**
     * syncs the data to file
     */
    flush() {
        if (this.fd) {
            this.commit();
        }
    }
    ;
    /**
     * Renames the file you are working on.
     *
     * Must be full file path and file name.
     *
     * Keeps write / read position.
     *
     * Note: This is permanent and can't be undone.
     *
     * @param {string} newFilePath - New full file path and name.
     */
    renameFile(newFilePath) {
        if (this.isMemoryMode) {
            return;
        }
        try {
            this.close();
            _a$1.fs.renameSync(this.filePath, newFilePath);
        }
        catch (error) {
            throw new Error(error);
        }
        this.filePath = newFilePath;
        this.open();
    }
    ;
    /**
     * Deletes the working file.
     *
     * Note: This is permanent and can't be undone.
     *
     * It doesn't send the file to the recycling bin for recovery.
     */
    deleteFile() {
        if (this.isMemoryMode) {
            return;
        }
        if (this.readOnly) {
            throw new Error("Can't delete file in readonly mode!");
        }
        try {
            this.close();
            _a$1.fs.unlinkSync(this.filePath);
        }
        catch (error) {
            throw new Error(error);
        }
        this.filePath = null;
    }
    ;
    ///////////////////////////////
    // #region ENDIANNESS
    ///////////////////////////////
    /**
     *
     * Change endian, defaults to little.
     *
     * Can be changed at any time, doesn't loose position.
     *
     * @param {endian} endian - endianness ``big`` or ``little``
     */
    endianness(endian) {
        if (endian == undefined || typeof endian != "string") {
            throw new TypeError("Endian must be big or little");
        }
        if (endian != undefined && !(endian == "big" || endian == "little")) {
            throw new TypeError("Endian must be big or little");
        }
        this.endian = endian;
    }
    ;
    /**
     * Sets endian to big.
     */
    bigEndian() {
        this.endianness("big");
    }
    ;
    /**
     * Sets endian to big.
     */
    big() {
        this.endianness("big");
    }
    ;
    /**
     * Sets endian to big.
     */
    be() {
        this.endianness("big");
    }
    ;
    /**
     * Sets endian to little.
     */
    littleEndian() {
        this.endianness("little");
    }
    ;
    /**
     * Sets endian to little.
     */
    little() {
        this.endianness("little");
    }
    ;
    /**
     * Sets endian to little.
     */
    le() {
        this.endianness("little");
    }
    ;
    ///////////////////////////////
    // #region SIZE
    ///////////////////////////////
    /**
     * Size in bytes of the current buffer.
     *
     * @returns {number} size
     */
    get length() {
        return this.size;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     * @returns {number} size
     */
    get len() {
        return this.size;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     *  @returns {number} size
     */
    get fileSize() {
        return this.size;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     * @returns {number} size
     */
    get FileSize() {
        return this.size;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get lengthBits() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get sizeBits() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get fileBitSize() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     *  @returns {number} size
     */
    get fileSizeBits() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get lenBits() {
        return this.bitSize;
    }
    ;
    ///////////////////////////////
    // #region POSITION
    ///////////////////////////////
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get offset() {
        return this.#offset;
    }
    ;
    /**
     * Get the current byte position;
     *
     * @returns {number} current byte position
     */
    get off() {
        return this.offset;
    }
    ;
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get getOffset() {
        return this.offset;
    }
    ;
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get tell() {
        return this.offset;
    }
    ;
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get FTell() {
        return this.offset;
    }
    ;
    /**
     * Get the current byte position;
     *
     * @returns {number} current byte position
     */
    get saveOffset() {
        return this.offset;
    }
    ;
    /**
     * Get the current byte position;
     *
     * @returns {number} current byte position
     */
    get byteOffset() {
        return this.offset;
    }
    ;
    /**
     * Set the current byte position.
     *
     * Same as {@link goto}
     */
    set offset(value) {
        this.goto(value);
    }
    ;
    /**
     * Set the current byte position.
     *
     * Same as {@link goto}
     */
    set setOffset(value) {
        this.offset = value;
    }
    ;
    /**
     * Set the current byte position.
     *
     * Same as {@link goto}
     */
    set setByteOffset(value) {
        this.offset = value;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get bitOffset() {
        return (this.#offset * 8) + this.#insetBit;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get offsetBits() {
        return this.bitOffset;
    }
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get getBitOffset() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get saveBitOffset() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get FTellBits() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get tellBits() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get offBits() {
        return this.bitOffset;
    }
    ;
    /**
     * Set the current bit position.
     *
     * Same as {@link goto}
     */
    set bitOffset(value) {
        this.goto(value - (value % 8), value % 8);
    }
    ;
    /**
     * Set the current bit position.
     */
    set setOffsetBits(value) {
        this.bitOffset = value;
    }
    ;
    /**
     * Set the current bit position.
     */
    set setBitOffset(value) {
        this.setOffsetBits = value;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get insetBit() {
        return this.#insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get getInsetBit() {
        return this.insetBit;
    }
    ;
    /**
     * Set the current bit position with in the current byte (0-7).
     */
    set insetBit(value) {
        this.goto(this.offset, value % 8);
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get saveInsetBit() {
        return this.insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get inBit() {
        return this.insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get bitTell() {
        return this.insetBit;
    }
    ;
    /**
     * Set the current bit position with in the byte (0-7).
     */
    set setInsetBit(value) {
        this.insetBit = value;
    }
    ;
    /**
     * Size in bytes of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get remain() {
        return this.size - this.#offset;
    }
    ;
    /**
     * Size in bytes of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get remainBytes() {
        return this.remain;
    }
    ;
    /**
     * Size in bytes of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get FEoF() {
        return this.remainBytes;
    }
    ;
    /**
     * Size in bits of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get remainBits() {
        return (this.size * 8) - this.bitOffset;
    }
    ;
    /**
     * Size in bits of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get FEoFBits() {
        return this.remainBits;
    }
    ;
    /**
     * Row line of the file (16 bytes per row).
     *
     * @returns {number} size
     */
    get getLine() {
        return Math.abs(Math.floor((this.#offset - 1) / 16));
    }
    ;
    /**
     * Row line of the file (16 bytes per row).
     *
     * @returns {number} size
     */
    get row() {
        return this.getLine;
    }
    ;
    ///////////////////////////////
    // #region FINISHING
    ///////////////////////////////
    /**
     * Returns current data.
     *
     * Note: Will remove all data after current position if ``growthIncrement`` was set and you expanded data past the end once.
     *
     * Use ``.data`` instead if you want the full buffer data.
     *
     * @returns {ReturnMapping<DataType>} ``Buffer`` or ``Uint8Array``
     */
    get() {
        if (this.growthIncrement != 0 && this.wasExpanded) {
            this.trim();
        }
        return this.#data;
    }
    ;
    /**
     * Returns current data.
     *
     * Note: Will remove all data after current position if ``growthIncrement`` was set and you expanded data past the end once.
     *
     * Use ``.data`` instead if you want the full buffer data.
     *
     * @returns {ReturnMapping<DataType>} ``Buffer`` or ``Uint8Array``
     */
    getFullBuffer() {
        return this.get();
    }
    ;
    /**
     * Returns current data.
     *
     * Note: Will remove all data after current position if ``growthIncrement`` was set and you expanded data past the end once.
     *
     * Use ``.data`` instead if you want the full buffer data.
     *
     * @returns {ReturnMapping<DataType>} ``Buffer`` or ``Uint8Array``
     */
    return() {
        return this.get();
    }
    ;
    /**
     * Returns and remove data.
     *
     * Commits any changes to file when editing a file.
     */
    end() {
        return this.close();
    }
    ;
    /**
     * removes data.
     *
     * Commits any changes to file when editing a file.
     */
    done() {
        return this.end();
    }
    ;
    /**
     * removes data.
     *
     * Commits any changes to file when editing a file.
     */
    finished() {
        return this.end();
    }
    ;
    ///////////////////////////////
    // #region HEX DUMP
    ///////////////////////////////
    /**
    * Creates hex dump string. Will console log or return string if set in options.
    *
    * @param {object} options
    * @param {hexdumpOptions?} options - hex dump options
    * @param {number?} options.length - number of bytes to log, default ``192`` or end of data
    * @param {number?} options.startByte - byte to start dump (default ``0``)
    * @param {boolean?} options.suppressUnicode - Suppress unicode character preview for even columns.
    * @param {boolean?} options.returnString - Returns the hex dump string instead of logging it.
    */
    hexdump(options = {}) {
        const length = options?.length ?? 192;
        const startByte = options?.startByte ?? this.#offset;
        const endByte = Math.min(startByte + length, this.size);
        const newSize = endByte - startByte;
        if (startByte > this.size || endByte > this.size) {
            throw new RangeError("Hexdump amount is outside of data size: " + newSize + " of " + endByte);
        }
        return _hexDump(this.data, options, startByte, endByte);
    }
    ;
    /**
     * Turn hexdump on error off (default on).
     */
    errorDumpOff() {
        this.errorDump = false;
    }
    ;
    /**
     * Turn hexdump on error on (default on).
     */
    errorDumpOn() {
        this.errorDump = true;
    }
    ;
    ///////////////////////////////
    // #region STRICT MODE
    ///////////////////////////////
    /**
     * Disallows extending data if position is outside of max size.
     */
    restrict() {
        this.strict = true;
    }
    ;
    /**
     * Allows extending data if position is outside of max size.
     */
    unrestrict() {
        this.strict = false;
    }
    ;
    ///////////////////////////////
    // #region   FIND 
    ///////////////////////////////
    /**
     * Searches for position of array of byte values from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {Uint8Array | Buffer | Array<number>} bytesToFind
     */
    findBytes(bytesToFind) {
        if (Array.isArray(bytesToFind)) {
            bytesToFind = new Uint8Array(bytesToFind);
        }
        this.open();
        if (this.isBuffer(this.data)) {
            var offset = this.data.subarray(this.#offset, this.size).indexOf(bytesToFind);
            if (offset == -1) {
                return -1;
            }
            return offset + this.#offset;
        }
        // this.data == Uint8Array
        for (let i = this.#offset; i <= this.size - bytesToFind.length; i++) {
            var match = true;
            for (let j = 0; j < bytesToFind.length; j++) {
                if (this.data[i + j] !== bytesToFind[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i; // Found the string, return the index
            }
        }
        return -1;
    }
    ;
    /**
     * Searches for byte position of string from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {string} string - String to search for.
     * @param {1|2|4} bytesPerChar - how many bytes each character should take up
     */
    findString(string, bytesPerChar = 1) {
        const encoded = textEncode(string, bytesPerChar);
        return this.findBytes(encoded);
    }
    ;
    #findNumber(value, bits, unsigned, endian = this.endian) {
        this.#checkSize(Math.floor(bits / 8), 0, this.#offset);
        for (let z = this.#offset; z <= (this.size - (bits / 8)); z++) {
            var offsetInBits = 0;
            var value = 0;
            for (var i = 0; i < bits;) {
                const remaining = bits - i;
                const bitOffset = offsetInBits & 7;
                const currentByte = this.data[z + (offsetInBits >> 3)];
                const read = Math.min(remaining, 8 - bitOffset);
                if (endian == "big") {
                    let mask = ~(0xFF << read);
                    let readBits = (currentByte >> (8 - read - bitOffset)) & mask;
                    value <<= read;
                    value |= readBits;
                }
                else {
                    let mask = ~(0xFF << read);
                    let readBits = (currentByte >> bitOffset) & mask;
                    value |= readBits << i;
                }
                offsetInBits += read;
                i += read;
            }
            if (unsigned || bits <= 7) {
                value = value >>> 0;
            }
            else {
                if (bits !== 32 && value & (1 << (bits - 1))) {
                    value |= -1 ^ ((1 << bits) - 1);
                }
            }
            if (value === value) {
                return z - this.#offset; // Found the byte, return the index from current
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for byte value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    findByte(value, unsigned = true, endian = this.endian) {
        return this.#findNumber(value, 8, unsigned, endian);
    }
    ;
    /**
     * Searches for short value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    findShort(value, unsigned = true, endian = this.endian) {
        return this.#findNumber(value, 16, unsigned, endian);
    }
    ;
    /**
     * Searches for integer value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    findInt(value, unsigned = true, endian = this.endian) {
        return this.#findNumber(value, 32, unsigned, endian);
    }
    ;
    /**
     * Searches for 64 bit value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {BigValue} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    findInt64(value, unsigned = true, endian = this.endian) {
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        this.#checkSize(8, 0, this.#offset);
        for (let z = this.#offset; z <= (this.size - 8); z++) {
            var startingValue = BigInt(0);
            if (endian == "little") {
                for (let i = 0; i < 8; i++) {
                    startingValue = startingValue | BigInt((this.data[z + i] & 0xFF)) << BigInt(8 * i);
                }
                if (!unsigned) {
                    if (startingValue & (BigInt(1) << BigInt(63))) {
                        startingValue -= BigInt(1) << BigInt(64);
                    }
                }
            }
            else {
                for (let i = 0; i < 8; i++) {
                    startingValue = (startingValue << BigInt(8)) | BigInt((this.data[z + i] & 0xFF));
                }
                if (!unsigned) {
                    if (startingValue & (BigInt(1) << BigInt(63))) {
                        startingValue -= BigInt(1) << BigInt(64);
                    }
                }
            }
            if (startingValue == BigInt(value)) {
                return z;
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for half float value position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {endian} endian - endianness of value (default set endian).
     */
    findHalfFloat(value, endian = this.endian) {
        this.#checkSize(2, 0, this.#offset);
        for (let z = this.#offset; z <= (this.size - 2); z++) {
            var startingValue = 0;
            if (endian == "little") {
                startingValue = ((this.data[z + 1] & 0xFFFF) << 8) | (this.data[z] & 0xFFFF);
            }
            else {
                startingValue = ((this.data[z] & 0xFFFF) << 8) | (this.data[z + 1] & 0xFFFF);
            }
            const sign = (startingValue & 0x8000) >> 15;
            const exponent = (startingValue & 0x7C00) >> 10;
            const fraction = startingValue & 0x03FF;
            var floatValue;
            if (exponent === 0) {
                if (fraction === 0) {
                    floatValue = (sign === 0) ? 0 : -0; // +/-0
                }
                else {
                    // Denormalized number
                    floatValue = (sign === 0 ? 1 : -1) * Math.pow(2, -14) * (fraction / 0x0400);
                }
            }
            else if (exponent === 0x1F) {
                if (fraction === 0) {
                    floatValue = (sign === 0) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
                }
                else {
                    floatValue = Number.NaN;
                }
            }
            else {
                // Normalized number
                floatValue = (sign === 0 ? 1 : -1) * Math.pow(2, exponent - 15) * (1 + fraction / 0x0400);
            }
            if (floatValue === value) {
                return z; // Found the number, return the index
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for float value position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {endian} endian - endianness of value (default set endian).
     */
    findFloat(value, endian = this.endian) {
        this.#checkSize(4, 0, this.#offset);
        for (let z = this.#offset; z <= (this.size - 4); z++) {
            var startingValue = 0;
            if (endian == "little") {
                startingValue = ((this.data[z + 3] & 0xFF) << 24) |
                    ((this.data[z + 2] & 0xFF) << 16) |
                    ((this.data[z + 1] & 0xFF) << 8) |
                    (this.data[z] & 0xFF);
            }
            else {
                startingValue = ((this.data[z] & 0xFF) << 24) |
                    ((this.data[z + 1] & 0xFF) << 16) |
                    ((this.data[z + 2] & 0xFF) << 8) |
                    (this.data[z + 3] & 0xFF);
            }
            const isNegative = (startingValue & 0x80000000) !== 0 ? 1 : 0;
            // Extract the exponent and fraction parts
            const exponent = (startingValue >> 23) & 0xFF;
            const fraction = startingValue & 0x7FFFFF;
            // Calculate the float value
            var floatValue;
            if (exponent === 0) {
                // Denormalized number (exponent is 0)
                floatValue = Math.pow(-1, isNegative) * Math.pow(2, -126) * (fraction / Math.pow(2, 23));
            }
            else if (exponent === 0xFF) {
                // Infinity or NaN (exponent is 255)
                floatValue = fraction === 0 ? (isNegative ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY) : Number.NaN;
            }
            else {
                // Normalized number
                floatValue = Math.pow(-1, isNegative) * Math.pow(2, exponent - 127) * (1 + fraction / Math.pow(2, 23));
            }
            if (floatValue === value) {
                return z; // Found the number, return the index
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for double float value position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {endian} endian - endianness of value (default set endian).
     */
    findDoubleFloat(value, endian = this.endian) {
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        this.#checkSize(8, 0, this.#offset);
        for (let z = this.#offset; z <= (this.size - 8); z++) {
            var startingValue = BigInt(0);
            if (endian == "little") {
                for (let i = 0; i < 8; i++) {
                    startingValue = startingValue | BigInt((this.data[z + i] & 0xFF)) << BigInt(8 * i);
                }
            }
            else {
                for (let i = 0; i < 8; i++) {
                    startingValue = (startingValue << BigInt(8)) | BigInt((this.data[z + i] & 0xFF));
                }
            }
            const sign = (startingValue & BigInt("9223372036854775808")) >> BigInt(63);
            const exponent = Number((startingValue & BigInt("9218868437227405312")) >> BigInt(52)) - 1023;
            const fraction = Number(startingValue & BigInt("4503599627370495")) / Math.pow(2, 52);
            var floatValue;
            if (exponent == -1023) {
                if (fraction == 0) {
                    floatValue = (sign == BigInt(0)) ? 0 : -0; // +/-0
                }
                else {
                    // Denormalized number
                    floatValue = (sign == BigInt(0) ? 1 : -1) * Math.pow(2, -1022) * fraction;
                }
            }
            else if (exponent == 1024) {
                if (fraction == 0) {
                    floatValue = (sign == BigInt(0)) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
                }
                else {
                    floatValue = Number.NaN;
                }
            }
            else {
                // Normalized number
                floatValue = (sign == BigInt(0) ? 1 : -1) * Math.pow(2, exponent) * (1 + fraction);
            }
            if (floatValue == value) {
                return z;
            }
        }
        return -1; // number not found
    }
    ;
    ///////////////////////////////
    // #region MOVE TO
    ///////////////////////////////
    /**
     * Aligns current byte position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} number - Byte to align
     */
    align(number) {
        const a = this.#offset % number;
        if (a) {
            this.skip(number - a);
        }
    }
    ;
    /**
     * Reverse aligns current byte position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} number - Byte to align
     */
    alignRev(number) {
        const a = this.#offset % number;
        if (a) {
            this.skip(a * -1);
        }
    }
    ;
    /**
     * Offset current byte or bit position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} bytes - Bytes to skip
     * @param {number} bits - Bits to skip
     */
    skip(bytes, bits) {
        var newOffset = ((bytes + this.#offset) + Math.ceil((this.#insetBit + bits) / 8));
        if (bits && bits < 0) {
            newOffset = Math.floor((((bytes + this.#offset) * 8) + this.#insetBit + bits) / 8);
        }
        this.#confrimSize(newOffset);
        // Adjust byte offset based on bit overflow
        this.#offset += Math.floor((this.#insetBit + bits) / 8);
        // Adjust bit offset
        this.#insetBit = (this.#insetBit + normalizeBitOffset(bits)) % 8;
        // Adjust byte offset based on byte overflow
        this.#offset += bytes;
        // Ensure bit offset stays between 0-7
        this.#insetBit = Math.min(Math.max(this.#insetBit, 0), 7);
        // Ensure offset doesn't go negative
        this.#offset = Math.max(this.#offset, 0);
        return;
    }
    ;
    /**
    * Offset current byte or bit position.
    *
    * Note: Will extend array if strict mode is off and outside of max size.
    *
    * @param {number} bytes - Bytes to skip
    * @param {number} bits - Bits to skip
    */
    jump(bytes, bits) {
        this.skip(bytes, bits);
    }
    ;
    /**
     * Offset current byte or bit position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} bytes - Bytes to skip
     * @param {number} bits - Bits to skip
     */
    seek(bytes, bits) {
        return this.skip(bytes, bits);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    goto(byte = 0, bit = 0) {
        var newOffset = byte + Math.ceil(bit / 8);
        if (bit && bit < 0) {
            newOffset = Math.floor(((byte * 8) + bit) / 8);
        }
        this.#confrimSize(newOffset);
        this.#offset = byte;
        // Adjust byte offset based on bit overflow
        this.#offset += Math.floor(bit / 8);
        // Adjust bit offset
        this.#insetBit = normalizeBitOffset(bit) % 8;
        // Ensure bit offset stays between 0-7
        this.#insetBit = Math.min(Math.max(this.#insetBit, 0), 7);
        // Ensure offset doesn't go negative
        this.#offset = Math.max(this.#offset, 0);
        return;
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    FSeek(byte, bit) {
        return this.goto(byte, bit);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    pointer(byte, bit) {
        return this.goto(byte, bit);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    warp(byte, bit) {
        return this.goto(byte, bit);
    }
    ;
    /**
     * Set byte and bit position to start of data.
     */
    rewind() {
        this.#offset = 0;
        this.#insetBit = 0;
    }
    ;
    /**
     * Set byte and bit position to start of data.
     */
    gotoStart() {
        return this.rewind();
    }
    ;
    /**
     * Set current byte and bit position to end of data.
     */
    last() {
        this.#offset = this.size;
        this.#insetBit = 0;
    }
    ;
    /**
     * Set current byte and bit position to end of data.
     */
    gotoEnd() {
        this.last();
    }
    ;
    /**
     * Set byte and bit position to start of data.
     */
    EoF() {
        this.last();
    }
    ;
    ///////////////////////////////
    // #region REMOVE
    ///////////////////////////////
    /**
     * Deletes part of data from start to current byte position unless supplied, returns removed.
     *
     * Note: Errors in strict mode.
     *
     * @param {number} startOffset - Start location (default 0)
     * @param {number} endOffset - End location (default current position)
     * @param {boolean} consume - Move position to end of removed data (default false)
     * @returns {ReturnMapping<DataType>} Removed data as ``Buffer`` or ``Uint8Array``
     */
    delete(startOffset = 0, endOffset = this.#offset, consume = false) {
        if (this.readOnly || this.strict) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("\x1b[33m[Strict mode]\x1b[0m: Can not remove data in strict mode: endOffset " + endOffset + " of " + this.size);
        }
        this.open();
        startOffset = Math.abs(startOffset);
        const removeLen = endOffset - startOffset;
        if (startOffset < 0 || endOffset > this.size) {
            throw new RangeError('Remove range out of bounds');
        }
        if (removeLen <= 0) {
            if (this.isMemoryMode) {
                if (this.isBuffer(this.data)) {
                    return Buffer.alloc(0);
                }
                else {
                    return new Uint8Array(0);
                }
            }
            else {
                return Buffer.alloc(0);
            }
        }
        this.#confrimSize(endOffset);
        const dataRemoved = this.data.subarray(startOffset, endOffset);
        const part1 = this.data.subarray(0, startOffset);
        const part2 = this.data.subarray(endOffset, this.size);
        if (this.isBuffer(this.data)) {
            this.data = Buffer.concat([part1, part2]);
        }
        else {
            const newBuf = new Uint8Array(part1.byteLength + part2.byteLength);
            newBuf.set(part1, 0);
            newBuf.set(part2, part1.byteLength);
            this.data = newBuf;
        }
        this.size = this.data.length;
        this.bitSize = this.data.length * 8;
        if (consume) {
            this.#offset = startOffset;
            this.#insetBit = 0;
        }
        return dataRemoved;
    }
    ;
    /**
     * Deletes part of data from current byte position to end, returns removed.
     *
     * Note: Errors in strict mode.
     *
     * @returns {ReturnMapping<DataType>} Removed data as ``Buffer`` or ``Uint8Array``
     */
    clip() {
        return this.delete(this.#offset, this.size, false);
    }
    ;
    /**
     * Deletes part of data from current byte position to end, returns removed.
     *
     * Note: Errors in strict mode.
     *
     * @returns {ReturnMapping<DataType>} Removed data as ``Buffer`` or ``Uint8Array``
     */
    trim() {
        return this.delete(this.#offset, this.size, false);
    }
    ;
    /**
     * Deletes part of data from current byte position to supplied length, returns removed.
     *
     * Note: Errors in strict mode.
     *
     * @param {number} length - Length of data in bytes to remove
     * @param {boolean} consume - Move position to end of removed data (default false)
     * @returns {ReturnMapping<DataType>} Removed data as ``Buffer`` or ``Uint8Array``
     */
    crop(length = 0, consume = false) {
        return this.delete(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Deletes part of data from current position to supplied length, returns removed.
     *
     * Note: Only works in strict mode.
     *
     * @param {number} length - Length of data in bytes to remove
     * @param {boolean} consume - Move position to end of removed data (default false)
     * @returns {ReturnMapping<DataType>} Removed data as ``Buffer`` or ``Uint8Array``
     */
    drop(length = 0, consume = false) {
        return this.delete(this.#offset, this.#offset + length, consume);
    }
    ;
    ///////////////////////////////
    // #region REPLACE
    ///////////////////////////////
    /**
     * Replaces data in data.
     *
     * Note: Errors on strict mode if past end of data.
     *
     * @param {Uint8Array | Buffer} data - ``Uint8Array`` or ``Buffer`` to replace in data
     * @param {number} offset - Offset to add it at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default false)
     */
    replace(data, offset = this.#offset, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't replace data in readOnly mode!");
        }
        this.open();
        // input is Buffer
        if (this.isBuffer(data)) {
            if (this.isUint8Array(this.data)) {
                // source is Uint8Array
                data = new Uint8Array(data);
            }
        }
        else {
            // input is Uint8Array
            if (this.isBuffer(this.data)) {
                // source is Buffer
                data = Buffer.from(data);
            }
        }
        const neededSize = offset + data.length;
        this.#confrimSize(neededSize);
        const part1 = this.data.subarray(0, neededSize - data.length);
        const part2 = this.data.subarray(neededSize, this.size);
        if (this.isBuffer(this.data)) {
            this.data = Buffer.concat([part1, data, part2]);
        }
        else {
            const newBuf = new Uint8Array(part1.byteLength + data.byteLength + part2.byteLength);
            newBuf.set(part1, 0);
            newBuf.set(data, part1.byteLength);
            newBuf.set(part2, part1.byteLength + data.byteLength);
            this.data = newBuf;
        }
        this.size = this.data.length;
        this.bitSize = this.data.length * 8;
        if (consume) {
            this.#offset = offset + data.length;
            this.#insetBit = 0;
        }
    }
    ;
    /**
     * Replaces data in data.
     *
     * Note: Errors on strict mode.
     *
     * @param {Uint8Array | Buffer} data - ``Uint8Array`` or ``Buffer`` to replace in data
     * @param {number} offset - Offset to add it at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default false)
     */
    overwrite(data, offset = this.#offset, consume = false) {
        return this.replace(data, offset, consume);
    }
    ;
    ///////////////////////////////
    // #region  COPY OUT
    ///////////////////////////////
    /**
     * Returns part of data from current byte position to end of data unless supplied.
     *
     * @param {number} startOffset - Start location (default current position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move position to end of lifted data (default false)
     * @param {number} fillValue - Byte value to to fill returned data (does NOT fill unless supplied)
     * @returns {ReturnMapping<DataType>} Selected data as ``Uint8Array`` or ``Buffer``
     */
    fill(startOffset = this.#offset, endOffset = this.size, consume = false, fillValue) {
        if (this.readOnly && fillValue != undefined) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't remove data in readonly mode!");
        }
        this.open();
        if (startOffset < 0 || endOffset > this.size) {
            throw new RangeError('Remove range out of bounds');
        }
        const removeLen = endOffset - startOffset;
        if (removeLen <= 0) {
            if (this.isMemoryMode) {
                if (this.isBuffer(this.data)) {
                    return Buffer.alloc(0);
                }
                else {
                    return new Uint8Array(0);
                }
            }
            else {
                return Buffer.alloc(0);
            }
        }
        if (endOffset > this.size && this.strict) {
            throw new Error('Cannot extend data while in strict mode. Use unrestrict() to enable.');
        }
        this.#confrimSize(endOffset);
        const dataRemoved = this.data.subarray(startOffset, endOffset);
        // without a fill value it's a basic lift
        if (fillValue != undefined) {
            const part1 = this.data.subarray(0, startOffset);
            const part2 = this.data.subarray(endOffset, this.size);
            const replacement = new Array(dataRemoved.length).fill(fillValue & 0xff);
            if (isBuffer(this.data)) {
                const buffReplacement = Buffer.from(replacement);
                this.data = Buffer.concat([part1, buffReplacement, part2]);
            }
            else {
                const newBuf = new Uint8Array(part1.byteLength + replacement.length + part2.byteLength);
                newBuf.set(part1, 0);
                newBuf.set(replacement, part1.byteLength);
                newBuf.set(part2, part1.byteLength + replacement.length);
                this.data = newBuf;
            }
            this.size = this.data.length;
            this.bitSize = this.data.length * 8;
        }
        if (consume) {
            this.#offset = endOffset;
            this.#insetBit = 0;
        }
        return dataRemoved;
    }
    ;
    /**
     * Returns part of data from current byte position to end of data unless supplied.
     *
     * @param {number} startOffset - Start location (default current position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move position to end of lifted data (default false)
     * @param {number} fillValue - Byte value to to fill returned data (does NOT fill unless supplied)
     * @returns {ReturnMapping<DataType>} Selected data as ``Uint8Array`` or ``Buffer``
     */
    lift(startOffset = this.#offset, endOffset = this.size, consume = false, fillValue) {
        return this.fill(startOffset, endOffset, consume, fillValue);
    }
    ;
    /**
     * Returns part of data from current byte position to end of data unless supplied.
     *
     * @param {number} startOffset - Start location (default current position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move position to end of lifted data (default false)
     * @returns {ReturnMapping<DataType>} Selected data as ``Uint8Array`` or ``Buffer``
     */
    subarray(startOffset = this.#offset, endOffset = this.size, consume = false) {
        return this.fill(startOffset, endOffset, consume);
    }
    /**
     * Extract data from current position to length supplied.
     *
     * Note: Does not affect supplied data.
     *
     * @param {number} length - Length of data in bytes to copy from current offset
     * @param {number} consume - Moves offset to end of length (default false)
     * @returns {ReturnMapping<DataType>} Selected data as ``Uint8Array`` or ``Buffer``
     */
    extract(length = 0, consume = false) {
        return this.fill(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Extract data from current position to length supplied.
     *
     * Note: Does not affect supplied data.
     *
     * @param {number} length - Length of data in bytes to copy from current offset
     * @param {number} consume - Moves offset to end of length (default false)
     * @returns {ReturnMapping<DataType>} Selected data as ``Uint8Array`` or ``Buffer``
     */
    slice(length = 0, consume = false) {
        return this.fill(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Extract data from current position to length supplied.
     *
     * Note: Does not affect supplied data.
     *
     * @param {number} length - Length of data in bytes to copy from current offset
     * @param {number} consume - Moves offset to end of length (default false)
     * @returns {ReturnMapping<DataType>} Selected data as ``Uint8Array`` or ``Buffer``
     */
    wrap(length = 0, consume = false) {
        return this.fill(this.#offset, this.#offset + length, consume);
    }
    ;
    ///////////////////////////////
    // #region   INSERT
    ///////////////////////////////
    /**
     * Inserts data into data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {number} offset - Byte position to add at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default true)
     */
    insert(data, offset = this.#offset, consume = true) {
        if (this.strict == true || this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error(`\x1b[33m[Strict mode]\x1b[0m: Can not insert data in strict mode. Use unrestrict() to enable.`);
        }
        if (!this.strict) {
            if (offset < 0 || offset > this.size) {
                throw new RangeError('Insert offset out of bounds');
            }
        }
        this.open();
        // input is Buffer
        if (this.isBuffer(data)) {
            if (this.isUint8Array(this.data)) {
                // source is Uint8Array
                data = new Uint8Array(data);
            }
        }
        else {
            // input is Uint8Array
            if (this.isBuffer(this.data)) {
                // source is Buffer
                data = Buffer.from(data);
            }
        }
        const insertLen = data?.length ?? 0;
        if (insertLen === 0) {
            return;
        }
        const part1 = this.data.subarray(0, offset);
        const part2 = this.data.subarray(offset, this.size);
        if (this.isBuffer(this.data)) {
            this.data = Buffer.concat([part1, data, part2]);
        }
        else {
            const newBuf = new Uint8Array(part1.byteLength + data.byteLength + part2.byteLength);
            newBuf.set(part1, 0);
            newBuf.set(data, part1.byteLength);
            newBuf.set(part2, part1.byteLength + data.byteLength);
            this.data = newBuf;
        }
        this.size = this.data.length;
        this.bitSize = this.data.length * 8;
        if (consume) {
            this.#offset = offset + data.length;
            this.#insetBit = 0;
        }
    }
    ;
    /**
     * Inserts data into data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {number} offset - Byte position to add at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default true)
     */
    place(data, offset = this.#offset, consume = true) {
        return this.insert(data, offset, consume);
    }
    ;
    /**
     * Adds data to start of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    unshift(data, consume = false) {
        return this.insert(data, 0, consume);
    }
    ;
    /**
     * Adds data to start of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    prepend(data, consume = false) {
        return this.insert(data, 0, consume);
    }
    ;
    /**
     * Adds data to end of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    push(data, consume = false) {
        return this.insert(data, this.size, consume);
    }
    ;
    /**
     * Adds data to end of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    append(data, consume = false) {
        return this.push(data, consume);
    }
    ;
    ///////////////////////////////
    // #region  MATH 
    ///////////////////////////////
    /**
     * XOR data.
     *
     * @param {number|string|Uint8Array|Buffer} xorKey - Value, string or array to XOR
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    xor(xorKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof xorKey == "string") {
            xorKey = new TextEncoder().encode(xorKey);
        }
        else if (!(this.isBufferOrUint8Array(xorKey) || typeof xorKey == "number")) {
            throw new Error("XOR must be a number, string, Uint8Array or Buffer");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _XOR(this.data, startOffset, Math.min(endOffset, this.size), xorKey);
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * XOR data.
     *
     * @param {number|string|Uint8Array|Buffer} xorKey - Value, string or array to XOR
     * @param {number} length - Length in bytes to XOR from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    xorThis(xorKey, length, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof xorKey == "number") {
            length = length ?? 1;
        }
        else if (typeof xorKey == "string") {
            xorKey = new TextEncoder().encode(xorKey);
            length = length ?? xorKey.length;
        }
        else if (this.isBufferOrUint8Array(xorKey)) {
            length = length ?? xorKey.length;
        }
        else {
            throw new Error("XOR must be a number, string, Uint8Array or Buffer");
        }
        return this.xor(xorKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * OR data
     *
     * @param {number|string|Uint8Array|Buffer} orKey - Value, string or array to OR
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    or(orKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof orKey == "string") {
            orKey = new TextEncoder().encode(orKey);
        }
        else if (!(this.isBufferOrUint8Array(orKey) || typeof orKey == "number")) {
            throw new Error("OR must be a number, string, Uint8Array or Buffer");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _OR(this.data, startOffset, Math.min(endOffset, this.size), orKey);
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * OR data.
     *
     * @param {number|string|Uint8Array|Buffer} orKey - Value, string or array to OR
     * @param {number} length - Length in bytes to OR from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    orThis(orKey, length, consume) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof orKey == "number") {
            length = length ?? 1;
        }
        else if (typeof orKey == "string") {
            orKey = new TextEncoder().encode(orKey);
            length = length ?? orKey.length;
        }
        else if (this.isBufferOrUint8Array(orKey)) {
            length = length ?? orKey.length;
        }
        else {
            throw new Error("OR must be a number, string, Uint8Array or Buffer");
        }
        return this.or(orKey, this.#offset, this.#offset + length, consume || false);
    }
    ;
    /**
     * AND data.
     *
     * @param {number|string|Uint8Array|Buffer} andKey - Value, string or array to AND
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    and(andKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof andKey == "string") {
            andKey = new TextEncoder().encode(andKey);
        }
        else if (!(typeof andKey == "object" || typeof andKey == "number")) {
            throw new Error("AND must be a number, string, number array or Buffer");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _AND(this.data, startOffset, Math.min(endOffset, this.size), andKey);
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * AND data.
     *
     * @param {number|string|Uint8Array|Buffer} andKey - Value, string or array to AND
     * @param {number} length - Length in bytes to AND from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    andThis(andKey, length, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof andKey == "number") {
            length = length ?? 1;
        }
        else if (typeof andKey == "string") {
            andKey = new TextEncoder().encode(andKey);
            length = length ?? andKey.length;
        }
        else if (this.isBufferOrUint8Array(andKey)) {
            length = length ?? andKey.length;
        }
        else {
            throw new Error("AND must be a number, string, Uint8Array or Buffer");
        }
        return this.and(andKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Add value to data.
     *
     * @param {number|string|Uint8Array|Buffer} addKey - Value, string or array to add to data
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    add(addKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof addKey == "string") {
            addKey = new TextEncoder().encode(addKey);
        }
        else if (!(typeof addKey == "object" || typeof addKey == "number")) {
            throw new Error("Add key must be a number, string, number array or Buffer");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _ADD(this.data, startOffset, Math.min(endOffset, this.size), addKey);
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * Add value to data.
     *
     * @param {number|string|Uint8Array|Buffer} addKey - Value, string or array to add to data
     * @param {number} length - Length in bytes to add from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    addThis(addKey, length, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof addKey == "number") {
            length = length ?? 1;
        }
        else if (typeof addKey == "string") {
            addKey = new TextEncoder().encode(addKey);
            length = length ?? addKey.length;
        }
        else if (this.isBufferOrUint8Array(addKey)) {
            length = length ?? addKey.length;
        }
        else {
            throw new Error("ADD must be a number, string, Uint8Array or Buffer");
        }
        return this.add(addKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Not data.
     *
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    not(startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _NOT(this.data, startOffset, Math.min(endOffset, this.size));
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * Not data.
     *
     * @param {number} length - Length in bytes to NOT from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    notThis(length = 1, consume = false) {
        return this.not(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Left shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to left shift data
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    lShift(shiftKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
        }
        else if (!(typeof shiftKey == "object" || typeof shiftKey == "number")) {
            throw new Error("Left shift must be a number, string, number array or Buffer");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _LSHIFT(this.data, startOffset, Math.min(endOffset, this.size), shiftKey);
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * Left shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to left shift data
     * @param {number} length - Length in bytes to left shift from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    lShiftThis(shiftKey, length, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof shiftKey == "number") {
            length = length ?? 1;
        }
        else if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
            length = length ?? shiftKey.length;
        }
        else if (this.isBufferOrUint8Array(shiftKey)) {
            length = length ?? shiftKey.length;
        }
        else {
            throw new Error("Left shift must be a number, string, Uint8Array or Buffer");
        }
        return this.lShift(shiftKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Right shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to right shift data
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    rShift(shiftKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
        }
        else if (!(typeof shiftKey == "object" || typeof shiftKey == "number")) {
            throw new Error("Right shift must be a number, string, number array or Buffer");
        }
        this.open();
        this.#confrimSize(endOffset);
        const returnData = _RSHIFT(this.data, startOffset, Math.min(endOffset, this.size), shiftKey);
        if (consume) {
            this.#offset = returnData.offset;
            this.#insetBit = returnData.bitoffset;
        }
    }
    ;
    /**
     * Right shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to right shift data
     * @param {number} length - Length in bytes to right shift from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    rShiftThis(shiftKey, length, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (typeof shiftKey == "number") {
            length = length ?? 1;
        }
        else if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
            length = length ?? shiftKey.length;
        }
        else if (this.isBufferOrUint8Array(shiftKey)) {
            length = length ?? shiftKey.length;
        }
        else {
            throw new Error("right shift must be a number, string, Uint8Array or Buffer");
        }
        return this.rShift(shiftKey, this.#offset, this.#offset + length, consume);
    }
    ;
    ///////////////////////////////
    // #region BIT READER
    ///////////////////////////////
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readBit(bits, unsigned = false, endian = this.endian, consume = true) {
        this.open();
        if (typeof bits != "number") {
            throw new TypeError("Enter number of bits to read");
        }
        if (bits == 0) {
            return 0;
        }
        if (bits <= 0 || bits > 32) {
            throw new Error('Bit length must be between 1 and 32. Got ' + bits);
        }
        const sizeNeeded = Math.floor(((bits - 1) + this.#insetBit) / 8) + this.#offset;
        this.#confrimSize(sizeNeeded);
        const bitStart = (this.#offset * 8) + this.#insetBit;
        const value = _rbit(this.data, bits, bitStart, endian, unsigned);
        if (consume) {
            this.#offset += Math.floor((bits + this.#insetBit) / 8);
            this.#insetBit = (bits + this.#insetBit) % 8;
        }
        return value;
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @returns {number}
     */
    readUBitBE(bits) {
        return this.readBit(bits, true, "big");
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @returns {number}
     */
    readUBitLE(bits) {
        return this.readBit(bits, true, "little");
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {number}
     */
    readBitBE(bits, unsigned) {
        return this.readBit(bits, unsigned, "big");
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {number}
     */
    readBitLE(bits, unsigned) {
        return this.readBit(bits, unsigned, "little");
    }
    ;
    /**
     *
     * Write bits, must have at least value and number of bits.
     *
     * ``Note``: When returning to a byte write, remaining bits are skipped.
     *
     * @param {number} value - value as int
     * @param {number} bits - number of bits to write
     * @param {boolean} unsigned - if value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeBit(value, bits, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readOnly mode!");
        }
        this.open();
        if (bits == 0) {
            return;
        }
        if (bits <= 0 || bits > 32) {
            throw new Error('Bit length must be between 1 and 32. Got ' + bits);
        }
        value = numberSafe(value, bits, unsigned);
        const endOffset = Math.ceil(((bits - 1) + this.#insetBit) / 8) + this.#offset;
        this.#confrimSize(endOffset);
        const offset = (this.#offset * 8) + this.#insetBit;
        _wbit(this.data, value, bits, offset, endian, unsigned);
        if (consume) {
            this.#offset += Math.floor((bits + this.#insetBit) / 8);
            this.#insetBit = (bits + this.#insetBit) % 8;
        }
        return;
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @returns number
     */
    writeUBitBE(value, bits) {
        return this.writeBit(value, bits, true, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @returns number
     */
    writeUBitLE(value, bits) {
        return this.writeBit(value, bits, true, "little");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @returns number
     */
    writeBitBE(value, bits, unsigned) {
        return this.writeBit(value, bits, unsigned, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @returns number
     */
    writeBitLE(value, bits, unsigned) {
        return this.writeBit(value, bits, unsigned, "little");
    }
    ;
    ///////////////////////////////
    // #region BYTE READER
    ///////////////////////////////
    /**
     * Read byte.
     *
     * @param {boolean} unsigned - if the value is unsigned or not
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readByte(unsigned = false, consume = true) {
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(1, 0, trueByte);
        var value;
        if (canInt8) {
            value = unsigned ? this.view.getUint8(trueByte) : this.view.getInt8(trueByte);
        }
        else {
            value = _rbyte(this.data, trueByte, unsigned);
        }
        if (consume) {
            this.#offset += 1;
            this.#insetBit = 0;
        }
        return value;
    }
    ;
    /**
     * Read unsigned byte.
     *
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readUByte(consume = true) {
        return this.readByte(true, consume);
    }
    ;
    /**
     * Read multiple bytes.
     *
     * @param {number} amount - amount of bytes to read
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {boolean} consume - move offset after read
     * @returns {Array<number>}
     */
    readBytes(amount, unsigned, consume = true) {
        const data = this.subarray(this.#offset, this.#offset + amount, consume);
        const returnArray = [];
        for (let i = 0; i < data.length; i++) {
            var value = data[0];
            if (unsigned) {
                returnArray.push(value & 0xFF);
            }
            else {
                returnArray.push(value > 127 ? value - 256 : value);
            }
        }
        return returnArray;
    }
    ;
    /**
     * Read multiple unsigned bytes.
     *
     * @param {number} amount - amount of bytes to read
     * @param {boolean} consume - move offset after read
     * @returns {ReturnMapping<DataType>}
     */
    readUBytes(amount, consume = true) {
        return this.subarray(this.#offset, this.#offset + amount, consume);
    }
    ;
    /**
     * Write byte.
     *
     * @param {number} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {boolean} consume - move offset after write
     */
    writeByte(value, unsigned = false, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(1, 0, trueByte);
        if (canInt8) {
            if (unsigned) {
                this.view.setUint8(trueByte, value);
            }
            else {
                this.view.setInt8(trueByte, value);
            }
        }
        else {
            _wbyte(this.data, numberSafe(value, 8, unsigned), trueByte, unsigned);
        }
        if (consume) {
            this.#offset += 1;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Write multiple bytes.
     *
     * @param {Array<number> | Buffer | Uint8Array} values - array of values as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {boolean} consume - move offset after write
     */
    writeBytes(values, unsigned, consume = true) {
        if (this.isBufferOrUint8Array(values)) {
            this.overwrite(values, this.offset, consume);
            return;
        }
        else {
            const data = new Uint8Array(values);
            this.overwrite(data, this.offset, consume);
            return;
        }
    }
    ;
    /**
     * Write multiple unsigned bytes.
     *
     * @param {Array<number> | Buffer | Uint8Array} values - array of values as int
     * @param {boolean} consume - move offset after write
     */
    writeUBytes(values, consume = true) {
        return this.writeBytes(values, true, consume);
    }
    ;
    /**
     * Write unsigned byte.
     *
     * @param {number} value - value as int
     * @param {boolean} consume - move offset after write
     */
    writeUByte(value, consume = true) {
        return this.writeByte(value, consume);
    }
    ;
    ///////////////////////////////
    // #region INT16 READER
    ///////////////////////////////
    /**
     * Read short.
     *
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readInt16(unsigned = false, endian = this.endian, consume = true) {
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(2, 0, trueByte);
        var value;
        if (canInt16) {
            if (unsigned) {
                value = this.view.getUint16(trueByte, endian == "little");
            }
            else {
                value = this.view.getInt16(trueByte, endian == "little");
            }
        }
        else {
            value = _rint16(this.data, trueByte, endian, unsigned);
        }
        if (consume) {
            this.#offset += 2;
            this.#insetBit = 0;
        }
        return value;
    }
    ;
    /**
     * Read unsigned short.
     *
     * @param {endian} endian - ``big`` or ``little``
     *
     * @returns {number}
     */
    readUInt16(endian = this.endian) {
        return this.readInt16(true, endian);
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {number}
     */
    readUInt16LE() {
        return this.readUInt16("little");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {number}
     */
    readUInt16BE() {
        return this.readUInt16("big");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {number}
     */
    readInt16LE() {
        return this.readInt16(false, "little");
    }
    ;
    /**
    * Read signed short in big endian.
    *
    * @returns {number}
    */
    readInt16BE() {
        return this.readInt16(false, "big");
    }
    ;
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeInt16(value, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(2, 0, trueByte);
        if (canInt16) {
            if (unsigned) {
                this.view.setUint16(trueByte, value, endian == "little");
            }
            else {
                this.view.setInt16(trueByte, value, endian == "little");
            }
        }
        else {
            _wint16(this.data, numberSafe(value, 16, unsigned), trueByte, endian, unsigned);
        }
        if (consume) {
            this.#offset += 2;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeUInt16(value, endian = this.endian) {
        return this.writeInt16(value, true, endian);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    writeUInt16BE(value) {
        return this.writeUInt16(value, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    writeUInt16LE(value) {
        return this.writeUInt16(value, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    writeInt16LE(value) {
        return this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    writeInt16BE(value) {
        return this.writeInt16(value, false, "big");
    }
    ;
    ///////////////////////////////
    // #region HALF FLOAT
    ///////////////////////////////
    /**
     * Read 16 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readHalfFloat(endian = this.endian, consume = true) {
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(2, 0, trueByte);
        var value;
        if (canFloat16) {
            value = this.view.getFloat16(trueByte, endian == "little");
        }
        else {
            value = _rhalffloat(this.data, trueByte, endian);
        }
        if (consume) {
            this.#offset += 2;
            this.#insetBit = 0;
        }
        return value;
    }
    ;
    /**
     * Read 16 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readFloat16(endian = this.endian, consume = true) {
        return this.readHalfFloat(endian, consume);
    }
    ;
    /**
    * Read 16 bit float.
    *
    * @returns {number}
    */
    readHalfFloatBE() {
        return this.readHalfFloat("big");
    }
    ;
    /**
    * Read 16 bit float.
    *
    * @returns {number}
    */
    readFloat16BE() {
        return this.readHalfFloat("big");
    }
    ;
    /**
     * Read 16 bit float.
     *
     * @returns {number}
     */
    readHalfFloatLE() {
        return this.readHalfFloat("little");
    }
    ;
    /**
     * Read 16 bit float.
     *
     * @returns {number}
     */
    readFloat16LE() {
        return this.readHalfFloat("little");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeHalfFloat(value, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(2, 0, trueByte);
        if (canFloat16) {
            this.view.setFloat16(trueByte, value, endian == "little");
        }
        else {
            _whalffloat(this.data, value, trueByte, endian);
        }
        if (consume) {
            this.#offset += 2;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeFloat16(value, endian = this.endian, consume = true) {
        return this.writeHalfFloat(value, endian, consume);
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    writeHalfFloatBE(value) {
        return this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloat16BE(value) {
        return this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    writeHalfFloatLE(value) {
        return this.writeHalfFloat(value, "little");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloat16LE(value) {
        return this.writeHalfFloat(value, "little");
    }
    ;
    ///////////////////////////////
    // #region INT32 READER
    ///////////////////////////////
    /**
     * Read 32 bit integer.
     *
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readInt32(unsigned = false, endian = this.endian, consume = true) {
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(4, 0, trueByte);
        var value;
        if (canInt32) {
            if (unsigned) {
                value = this.view.getUint32(trueByte, endian == "little");
            }
            else {
                value = this.view.getInt32(trueByte, endian == "little");
            }
        }
        else {
            value = _rint32(this.data, trueByte, endian, unsigned);
        }
        if (consume) {
            this.#offset += 4;
            this.#insetBit = 0;
        }
        return value;
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    readInt(endian = this.endian) {
        return this.readInt32(false, endian);
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    readInt32BE() {
        return this.readInt("big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    readInt32LE() {
        return this.readInt("little");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    readUInt32(endian = this.endian) {
        return this.readInt32(true, endian);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    readUInt(endian = this.endian) {
        return this.readInt32(true, endian);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    readUInt32BE() {
        return this.readUInt("big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    readUInt32LE() {
        return this.readUInt("little");
    }
    ;
    /**
     * Write 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeInt32(value, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(4, 0, trueByte);
        if (canInt32) {
            if (unsigned) {
                this.view.setUint32(trueByte, value, endian == "little");
            }
            else {
                this.view.setInt32(trueByte, value, endian == "little");
            }
        }
        else {
            _wint32(this.data, numberSafe(value, 32, unsigned), trueByte, endian, unsigned);
        }
        if (consume) {
            this.#offset += 4;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Write signed 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeInt(value, endian = this.endian) {
        return this.writeInt32(value, false, endian);
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    writeInt32LE(value) {
        return this.writeInt(value, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    writeInt32BE(value) {
        return this.writeInt(value, "big");
    }
    ;
    /**
     * Write unsigned 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeUInt(value, endian = this.endian) {
        return this.writeInt32(value, true, endian);
    }
    ;
    /**
     * Write unsigned 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeUInt32(value, endian = this.endian) {
        return this.writeUInt(value, endian);
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    writeUInt32BE(value) {
        return this.writeUInt32(value, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    writeUInt32LE(value) {
        return this.writeUInt32(value, "little");
    }
    ;
    ///////////////////////////////
    // #region FLOAT32 READER
    ///////////////////////////////
    /**
     * Read 32 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readFloat(endian = this.endian, consume = true) {
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(4, 0, trueByte);
        var value;
        if (canFloat32) {
            value = this.view.getFloat32(trueByte, endian == "little");
        }
        else {
            value = _rfloat(this.data, trueByte, endian);
        }
        if (consume) {
            this.#offset += 4;
            this.#insetBit = 0;
        }
        return value;
    }
    ;
    /**
     * Read 32 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     * @returns {number}
     */
    readFloat32(endian = this.endian, consume = true) {
        return this.readFloat(endian, consume);
    }
    ;
    /**
     * Read 32 bit float.
     *
     * @returns {number}
     */
    readFloatBE() {
        return this.readFloat("big");
    }
    ;
    /**
     * Read 32 bit float.
     *
     * @returns {number}
     */
    readFloat32BE() {
        return this.readFloat("big");
    }
    ;
    /**
     * Read 32 bit float.
     *
     * @returns {number}
     */
    readFloatLE() {
        return this.readFloat("little");
    }
    ;
    /**
     * Read 32 bit float.
     *
     * @returns {number}
     */
    readFloat32LE() {
        return this.readFloat("little");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeFloat(value, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(4, 0, trueByte);
        if (canFloat32) {
            this.view.setFloat32(trueByte, value, endian == "little");
        }
        else {
            _wfloat(this.data, value, trueByte, endian);
        }
        if (consume) {
            this.#offset += 4;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloatLE(value) {
        return this.writeFloat(value, "little");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloat32LE(value) {
        return this.writeFloat(value, "little");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloat32BE(value) {
        return this.writeFloat(value, "big");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloatBE(value) {
        return this.writeFloat(value, "big");
    }
    ;
    ///////////////////////////////
    // #region INT64 READER
    ///////////////////////////////
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    readInt64(unsigned = false, endian = this.endian, consume = true) {
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(8, 0, trueByte);
        var value;
        if (canBigInt64) {
            if (unsigned) {
                value = this.view.getBigUint64(trueByte, endian == "little");
            }
            else {
                value = this.view.getBigInt64(trueByte, endian == "little");
            }
        }
        else {
            value = _rint64(this.data, trueByte, endian, unsigned);
        }
        if (consume) {
            this.#offset += 8;
            this.#insetBit = 0;
        }
        if (this.enforceBigInt == true || (typeof value == "bigint" && !isSafeInt64(value))) {
            return value;
        }
        else {
            if (isSafeInt64(value)) {
                return Number(value);
            }
            else {
                throw new Error("Value is outside of number range and enforceBigInt is set to false. " + value);
            }
        }
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @returns {ReturnBigValueMapping<alwaysBigInt>}
     */
    readUInt64() {
        return this.readInt64(true);
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @returns {ReturnBigValueMapping<alwaysBigInt>}
     */
    readInt64BE() {
        return this.readInt64(false, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @returns {ReturnBigValueMapping<alwaysBigInt>}
     */
    readInt64LE() {
        return this.readInt64(false, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @returns {ReturnBigValueMapping<alwaysBigInt>}
     */
    readUInt64BE() {
        return this.readInt64(true, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @returns {ReturnBigValueMapping<alwaysBigInt>}
     */
    readUInt64LE() {
        return this.readInt64(true, "little");
    }
    ;
    /**
     * Write 64 bit integer.
     *
     * @param {BigValue} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    writeInt64(value, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(8, 0, trueByte);
        if (canBigInt64) {
            if (unsigned) {
                this.view.setBigInt64(trueByte, BigInt(value), endian == "little");
            }
            else {
                this.view.setBigUint64(trueByte, BigInt(value), endian == "little");
            }
        }
        else {
            _wint64(this.data, numberSafe(value, 64, unsigned), trueByte, endian, unsigned);
        }
        if (consume) {
            this.#offset += 8;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeUInt64(value, endian = this.endian) {
        return this.writeInt64(value, true, endian);
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    writeInt64LE(value) {
        return this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    writeInt64BE(value) {
        return this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    writeUInt64LE(value) {
        return this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    writeUInt64BE(value) {
        return this.writeInt64(value, true, "big");
    }
    ;
    ///////////////////////////////
    // #region FLOAT64 READER
    ///////////////////////////////
    /**
     * Read 64 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    readDoubleFloat(endian = this.endian, consume = true) {
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(8, 0, trueByte);
        var value;
        if (canFloat64) {
            value = this.view.getFloat64(trueByte, endian == "little");
        }
        else {
            if (!hasBigInt) {
                throw new Error("System doesn't support BigInt values.");
            }
            value = _rdfloat(this.data, trueByte, endian);
        }
        if (consume) {
            this.#offset += 8;
            this.#insetBit = 0;
        }
        return value;
    }
    ;
    /**
     * Read 64 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    readFloat64(endian = this.endian) {
        return this.readDoubleFloat(endian);
    }
    ;
    /**
     * Read 64 bit float.
     *
     * @returns {number}
     */
    readDoubleFloatBE() {
        return this.readDoubleFloat("big");
    }
    ;
    /**
     * Read 64 bit float.
     *
     * @returns {number}
     */
    readFloat64BE() {
        return this.readDoubleFloat("big");
    }
    ;
    /**
     * Read 64 bit float.
     *
     * @returns {number}
     */
    readDoubleFloatLE() {
        return this.readDoubleFloat("little");
    }
    ;
    /**
     * Read 64 bit float.
     *
     * @returns {number}
     */
    readFloat64LE() {
        return this.readDoubleFloat("little");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeDoubleFloat(value, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var trueByte = this.#offset;
        var trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#checkSize(8, 0, trueByte);
        if (canFloat64) {
            this.view.setFloat64(trueByte, value, endian == "little");
        }
        else {
            _wdfloat(this.data, value, trueByte, endian);
        }
        if (consume) {
            this.#offset += 8;
            this.#insetBit = 0;
        }
        return;
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    writeFloat64(value, endian = this.endian) {
        return this.writeDoubleFloat(value, endian);
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    writeDoubleFloatBE(value) {
        return this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloat64BE(value) {
        return this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    writeDoubleFloatLE(value) {
        return this.writeDoubleFloat(value, "little");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    writeFloat64LE(value) {
        return this.writeDoubleFloat(value, "little");
    }
    ;
    ///////////////////////////////
    // #region STRING READER
    ///////////////////////////////
    /**
    * Reads string, use options object for different types.
    *
    * @param {stringOptions} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings (in units NOT bytes)
    * @param {stringOptions["stringType"]?} options.stringType - utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthReadSize"]?} options.lengthReadSize - for pascal strings. 1, 2 or 4 byte length read size
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for wide-pascal, double-wide-pascal and utf-16, utf-32
    * @param {boolean} consume - move offset after read
    * @returns {string}
    */
    readString(options = this.strDefaults, consume = true) {
        this.open();
        var length = options.length;
        var stringType = options.stringType ?? 'utf-8';
        var terminateValue = options.terminateValue;
        var lengthReadSize = options.lengthReadSize ?? 1;
        var stripNull = options.stripNull ?? true;
        var endian = options.endian ?? this.endian;
        var encoding = options.encoding ?? 'utf-8';
        var terminate = terminateValue;
        var readLengthinBytes = 0;
        if (length != undefined) {
            switch (stringType) {
                case "utf-8":
                    readLengthinBytes = length;
                    break;
                case "utf-16":
                    readLengthinBytes = length * 2;
                    break;
                case "utf-32":
                    readLengthinBytes = length * 4;
                    break;
                default:
                    readLengthinBytes = length;
                    break;
            }
            this.#checkSize(readLengthinBytes);
        }
        else {
            readLengthinBytes = this.data.length - this.#offset;
        }
        if (terminateValue != undefined && typeof terminateValue == "number") {
            terminate = terminateValue & 0xFF;
        }
        else {
            terminate = 0;
        }
        const saved_offset = this.#offset;
        const saved_bitoffset = this.#insetBit;
        const str = _rstring(stringType, lengthReadSize, readLengthinBytes, terminate, stripNull, encoding, endian, this.readUByte.bind(this), this.readUInt16.bind(this), this.readUInt32.bind(this));
        if (!consume) {
            this.#offset = saved_offset;
            this.#insetBit = saved_bitoffset;
        }
        return str;
    }
    ;
    /**
    * Writes string, use options object for different types.
    *
    * @param {string} string - text string
    * @param {stringOptions?} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthWriteSize"]?} options.lengthWriteSize - for pascal strings. 1, 2 or 4 byte length write size
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for wide-pascal, double-wide-pascal and utf-16, utf-32
    * @param {boolean} consume - move offset after write
    */
    writeString(string, options = this.strDefaults, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readonly mode!");
        }
        this.open();
        var length = options.length;
        var stringType = options.stringType ?? 'utf-8';
        var terminateValue = options.terminateValue;
        var lengthWriteSize = options.lengthWriteSize ?? 1;
        var endian = options.endian ?? this.endian;
        var maxLengthValue = length ?? string.length;
        var strUnits = string.length;
        var maxBytes;
        switch (stringType) {
            case 'pascal':
                maxLengthValue = 255;
                if (length != undefined) {
                    maxLengthValue = length;
                }
                break;
            case 'wide-pascal':
                strUnits *= 2;
                maxLengthValue = 65535;
                if (length != undefined) {
                    maxLengthValue = length / 2;
                }
                break;
            case 'double-wide-pascal':
                strUnits *= 4;
                maxLengthValue = 4294967295;
                if (length != undefined) {
                    maxLengthValue = length / 4;
                }
                break;
        }
        if (terminateValue == undefined) {
            if (stringType == "ascii" || stringType == 'utf-8' ||
                stringType == 'utf-16' ||
                stringType == 'utf-32') {
                terminateValue = 0;
            }
            if (length != undefined) {
                terminateValue = undefined;
            }
        }
        var maxBytes = Math.min(strUnits, maxLengthValue);
        string = string.substring(0, maxBytes);
        var encodedString;
        var totalLength = string.length;
        switch (stringType) {
            case 'ascii':
            case 'utf-8':
            case 'pascal':
                {
                    encodedString = new TextEncoder().encode(string);
                    totalLength = encodedString.byteLength + 1;
                    if (stringType == 'utf-8' && length) {
                        totalLength = length;
                    }
                }
                break;
            case 'utf-16':
            case 'wide-pascal':
                {
                    const utf16Buffer = new Uint16Array(string.length);
                    for (let i = 0; i < string.length; i++) {
                        utf16Buffer[i] = string.charCodeAt(i);
                    }
                    encodedString = new Uint8Array(utf16Buffer.buffer);
                    totalLength = encodedString.byteLength + 2;
                    if (stringType == 'utf-16' && length) {
                        totalLength = length;
                    }
                }
                break;
            case 'utf-32':
            case 'double-wide-pascal':
                {
                    const utf32Buffer = new Uint32Array(string.length);
                    for (let i = 0; i < string.length; i++) {
                        utf32Buffer[i] = string.codePointAt(i);
                    }
                    encodedString = new Uint8Array(utf32Buffer.buffer);
                    totalLength = encodedString.byteLength + 4;
                    if (stringType == 'utf-32' && length) {
                        totalLength = length;
                    }
                }
                break;
        }
        this.#checkSize(totalLength, 0, this.#offset);
        const savedOffset = this.#offset;
        const savedBitOffset = this.#insetBit;
        _wstring(encodedString, stringType, endian, terminateValue, lengthWriteSize, this.writeUByte.bind(this), this.writeUInt16.bind(this), this.writeUInt32.bind(this));
        if (!consume) {
            this.#offset = savedOffset;
            this.#insetBit = savedBitOffset;
        }
        return;
    }
    ;
}
_a$1 = BiBase;

/**
 * Binary reader, includes bitfields and strings.
 *
 * @param {DataType} input - File path or a `Buffer` or `Uint8Array`. Always found in .{@link data}
 * @param {BiOptions?} options - Any options to set at start
 * @param {BiOptions["byteOffset"]?} [options.byteOffset = 0] - Byte offset to start reader (default `0`)
 * @param {BiOptions["bitOffset"]?} [options.bitOffset = 0] - Bit offset (overrides {@link byteOffset}) (default `0`)
 * @param {BiOptions["endianness"]?} [options.endianness = "little"] - Endianness `big` or `little` (default `little`)
 * @param {BiOptions["strict"]?} [options.strict = true] - Strict mode: if `true` does not extend supplied array on outside read or write (default `true`)
 * @param {BiOptions["growthIncrement"]?} [options.growthIncrement = 1048576] - Amount of data to add when extending the buffer array when strict mode is false (default `1 MiB`)
 * @param {BiOptions["enforceBigInt"]?} [options.enforceBigInt = false] - 64 bit value reads will always return `bigint`. (default `false`)
 * @param {BiOptions["readOnly"]?} [options.readOnly = true] - Allow data writes when reading a file (default `true` in reader)
 *
 * @since 2.0
 */
class BiReader extends BiBase {
    constructor(input, options = {}) {
        options.byteOffset = options.byteOffset ?? 0;
        options.bitOffset = options.bitOffset ?? 0;
        options.endianness = options.endianness ?? "little";
        options.strict = options.strict ?? true;
        options.growthIncrement = options.growthIncrement ?? 0x100000;
        options.enforceBigInt = options.enforceBigInt ?? false;
        options.readOnly = options.readOnly ?? true;
        if (input == undefined) {
            throw new Error("Can not start BiReader without data.");
        }
        super(input, options);
    }
    ;
    //
    // #region Bit Aliases
    //
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    bit(bits, unsigned, endian) {
        return this.readBit(bits, unsigned, endian);
    }
    ;
    /**
     * Bit field reader. Unsigned read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    ubit(bits, endian) {
        return this.readBit(bits, true, endian);
    }
    ;
    /**
     * Bit field reader. Unsigned big endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @returns {number}
     */
    ubitbe(bits) {
        return this.bit(bits, true, "big");
    }
    ;
    /**
     * Bit field reader. Big endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {number}
     */
    bitbe(bits, unsigned) {
        return this.bit(bits, unsigned, "big");
    }
    ;
    /**
     * Bit field reader. Unsigned little endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @returns {number}
     */
    ubitle(bits) {
        return this.bit(bits, true, "little");
    }
    ;
    /**
     * Bit field reader. Little endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {number}
     */
    bitle(bits, unsigned) {
        return this.bit(bits, unsigned, "little");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit1() {
        return this.bit(1);
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit1le() {
        return this.bit(1, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit1be() {
        return this.bit(1, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit1() {
        return this.bit(1, true);
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit1le() {
        return this.bit(1, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit1be() {
        return this.bit(1, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit2() {
        return this.bit(2);
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit2le() {
        return this.bit(2, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit2be() {
        return this.bit(2, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit2() {
        return this.bit(2, true);
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit2le() {
        return this.bit(2, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit2be() {
        return this.bit(2, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit3() {
        return this.bit(3);
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit3le() {
        return this.bit(3, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit3be() {
        return this.bit(3, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit3() {
        return this.bit(3, true);
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit3le() {
        return this.bit(3, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit3be() {
        return this.bit(3, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit4() {
        return this.bit(4);
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit4le() {
        return this.bit(4, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit4be() {
        return this.bit(4, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit4() {
        return this.bit(4, true);
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit4le() {
        return this.bit(4, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit4be() {
        return this.bit(4, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit5() {
        return this.bit(5);
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit5le() {
        return this.bit(5, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit5be() {
        return this.bit(5, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit5() {
        return this.bit(5, true);
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit5le() {
        return this.bit(5, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit5be() {
        return this.bit(5, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit6() {
        return this.bit(6);
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit6le() {
        return this.bit(6, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit6be() {
        return this.bit(6, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit6() {
        return this.bit(6, true);
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit6le() {
        return this.bit(6, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit6be() {
        return this.bit(6, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit7() {
        return this.bit(7);
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit7le() {
        return this.bit(7, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit7be() {
        return this.bit(7, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit7() {
        return this.bit(7, true);
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit7le() {
        return this.bit(7, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit7be() {
        return this.bit(7, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit8() {
        return this.bit(8);
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit8le() {
        return this.bit(8, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit8be() {
        return this.bit(8, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit8() {
        return this.bit(8, true);
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit8le() {
        return this.bit(8, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit8be() {
        return this.bit(8, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit9() {
        return this.bit(9);
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit9le() {
        return this.bit(9, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit9be() {
        return this.bit(9, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit9() {
        return this.bit(9, true);
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit9le() {
        return this.bit(9, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit9be() {
        return this.bit(9, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit10() {
        return this.bit(10);
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit10le() {
        return this.bit(10, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit10be() {
        return this.bit(10, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit10() {
        return this.bit(10, true);
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit10le() {
        return this.bit(10, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit10be() {
        return this.bit(10, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit11() {
        return this.bit(11);
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit11le() {
        return this.bit(11, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit11be() {
        return this.bit(11, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit11() {
        return this.bit(11, true);
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit11le() {
        return this.bit(11, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit11be() {
        return this.bit(11, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit12() {
        return this.bit(12);
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit12le() {
        return this.bit(12, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit12be() {
        return this.bit(12, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit12() {
        return this.bit(12, true);
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit12le() {
        return this.bit(12, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit12be() {
        return this.bit(12, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit13() {
        return this.bit(13);
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit13le() {
        return this.bit(13, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit13be() {
        return this.bit(13, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit13() {
        return this.bit(13, true);
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit13le() {
        return this.bit(13, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit13be() {
        return this.bit(13, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit14() {
        return this.bit(14);
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit14le() {
        return this.bit(14, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit14be() {
        return this.bit(14, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit14() {
        return this.bit(14, true);
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit14le() {
        return this.bit(14, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit14be() {
        return this.bit(14, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit15() {
        return this.bit(15);
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit15le() {
        return this.bit(15, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit15be() {
        return this.bit(15, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit15() {
        return this.bit(15, true);
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit15le() {
        return this.bit(15, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit15be() {
        return this.bit(15, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit16() {
        return this.bit(16);
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit16le() {
        return this.bit(16, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit16be() {
        return this.bit(16, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit16() {
        return this.bit(16, true);
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit16le() {
        return this.bit(16, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit16be() {
        return this.bit(16, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit17() {
        return this.bit(17);
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit17le() {
        return this.bit(17, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit17be() {
        return this.bit(17, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit17() {
        return this.bit(17, true);
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit17le() {
        return this.bit(17, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit17be() {
        return this.bit(17, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit18() {
        return this.bit(18);
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit18le() {
        return this.bit(18, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit18be() {
        return this.bit(18, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit18() {
        return this.bit(18, true);
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit18le() {
        return this.bit(18, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit18be() {
        return this.bit(18, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit19() {
        return this.bit(19);
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit19le() {
        return this.bit(19, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit19be() {
        return this.bit(19, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit19() {
        return this.bit(19, true);
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit19le() {
        return this.bit(19, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit19be() {
        return this.bit(19, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit20() {
        return this.bit(20);
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit20le() {
        return this.bit(20, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit20be() {
        return this.bit(20, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit20() {
        return this.bit(20, true);
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit20le() {
        return this.bit(20, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit20be() {
        return this.bit(20, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit21() {
        return this.bit(21);
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit21le() {
        return this.bit(21, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit21be() {
        return this.bit(21, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit21() {
        return this.bit(21, true);
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit21le() {
        return this.bit(21, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit21be() {
        return this.bit(21, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit22() {
        return this.bit(22);
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit22le() {
        return this.bit(22, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit22be() {
        return this.bit(22, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit22() {
        return this.bit(22, true);
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit22le() {
        return this.bit(22, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit22be() {
        return this.bit(22, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit23() {
        return this.bit(23);
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit23le() {
        return this.bit(23, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit23be() {
        return this.bit(23, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit23() {
        return this.bit(23, true);
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit23le() {
        return this.bit(23, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit23be() {
        return this.bit(23, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit24() {
        return this.bit(24);
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit24le() {
        return this.bit(24, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit24be() {
        return this.bit(24, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit24() {
        return this.bit(24, true);
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit24le() {
        return this.bit(24, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit24be() {
        return this.bit(24, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit25() {
        return this.bit(25);
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit25le() {
        return this.bit(25, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit25be() {
        return this.bit(25, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit25() {
        return this.bit(25, true);
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit25le() {
        return this.bit(25, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit25be() {
        return this.bit(25, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit26() {
        return this.bit(26);
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit26le() {
        return this.bit(26, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit26be() {
        return this.bit(26, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit26() {
        return this.bit(26, true);
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit26le() {
        return this.bit(26, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit26be() {
        return this.bit(26, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit27() {
        return this.bit(27);
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit27le() {
        return this.bit(27, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit27be() {
        return this.bit(27, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit27() {
        return this.bit(27, true);
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit27le() {
        return this.bit(27, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit27be() {
        return this.bit(27, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit28() {
        return this.bit(28);
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit28le() {
        return this.bit(28, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit28be() {
        return this.bit(28, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit28() {
        return this.bit(28, true);
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit28le() {
        return this.bit(28, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit28be() {
        return this.bit(28, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit29() {
        return this.bit(29);
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit29le() {
        return this.bit(29, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit29be() {
        return this.bit(29, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit29() {
        return this.bit(29, true);
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit29le() {
        return this.bit(29, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit29be() {
        return this.bit(29, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit30() {
        return this.bit(30);
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit30le() {
        return this.bit(30, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit30be() {
        return this.bit(30, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit30() {
        return this.bit(30, true);
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit30le() {
        return this.bit(30, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit30be() {
        return this.bit(30, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit31() {
        return this.bit(31);
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit31le() {
        return this.bit(31, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit31be() {
        return this.bit(31, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit31() {
        return this.bit(31, true);
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit31le() {
        return this.bit(31, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit31be() {
        return this.bit(31, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit32() {
        return this.bit(32);
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit32le() {
        return this.bit(32, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get bit32be() {
        return this.bit(32, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit32() {
        return this.bit(32, true);
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit32le() {
        return this.bit(32, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {number}
     */
    get ubit32be() {
        return this.bit(32, true, "big");
    }
    ;
    //
    // #region byte read
    //
    /**
     * Read byte.
     *
     * @returns {number}
     */
    get byte() {
        return this.readByte();
    }
    ;
    /**
     * Read byte.
     *
     * @returns {number}
     */
    get int8() {
        return this.readByte();
    }
    ;
    /**
     * Read unsigned byte.
     *
     * @returns {number}
     */
    get uint8() {
        return this.readByte(true);
    }
    ;
    /**
     * Read unsigned byte.
     *
     * @returns {number}
     */
    get ubyte() {
        return this.readByte(true);
    }
    ;
    //
    // #region short16 read
    //
    /**
     * Read short.
     *
     * @returns {number}
     */
    get int16() {
        return this.readInt16();
    }
    ;
    /**
     * Read short.
     *
     * @returns {number}
     */
    get short() {
        return this.readInt16();
    }
    ;
    /**
     * Read short.
     *
     * @returns {number}
     */
    get word() {
        return this.readInt16();
    }
    ;
    /**
     * Read unsigned short.
     *
     * @returns {number}
     */
    get uint16() {
        return this.readInt16(true);
    }
    ;
    /**
     * Read unsigned short.
     *
     * @returns {number}
     */
    get ushort() {
        return this.readInt16(true);
    }
    ;
    /**
     * Read unsigned short.
     *
     * @returns {number}
     */
    get uword() {
        return this.readInt16(true);
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {number}
     */
    get uint16le() {
        return this.readInt16(true, "little");
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {number}
     */
    get ushortle() {
        return this.readInt16(true, "little");
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {number}
     */
    get uwordle() {
        return this.readInt16(true, "little");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {number}
     */
    get int16le() {
        return this.readInt16(false, "little");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {number}
     */
    get shortle() {
        return this.readInt16(false, "little");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {number}
     */
    get wordle() {
        return this.readInt16(false, "little");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {number}
     */
    get uint16be() {
        return this.readInt16(true, "big");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {number}
     */
    get ushortbe() {
        return this.readInt16(true, "big");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {number}
     */
    get uwordbe() {
        return this.readInt16(true, "big");
    }
    ;
    /**
     * Read signed short in big endian.
     *
     * @returns {number}
     */
    get int16be() {
        return this.readInt16(false, "big");
    }
    ;
    /**
     * Read signed short in big endian.
     *
     * @returns {number}
     */
    get shortbe() {
        return this.readInt16(false, "big");
    }
    ;
    /**
     * Read signed short in big endian.
     *
     * @returns {number}
     */
    get wordbe() {
        return this.readInt16(false, "big");
    }
    ;
    //
    // #region half float read
    //
    /**
     * Read half float.
     *
     * @returns {number}
     */
    get halffloat() {
        return this.readHalfFloat();
    }
    ;
    /**
     * Read half float
     *
     * @returns {number}
     */
    get half() {
        return this.readHalfFloat();
    }
    ;
    /**
     * Read half float.
     *
     * @returns {number}
     */
    get halffloatbe() {
        return this.readHalfFloat("big");
    }
    ;
    /**
     * Read half float.
     *
     * @returns {number}
     */
    get halfbe() {
        return this.readHalfFloat("big");
    }
    ;
    /**
     * Read half float.
     *
     * @returns {number}
     */
    get halffloatle() {
        return this.readHalfFloat("little");
    }
    ;
    /**
     * Read half float.
     *
     * @returns {number}
     */
    get halfle() {
        return this.readHalfFloat("little");
    }
    ;
    //
    // #region int read
    //
    /**
     * Read 32 bit integer.
     *
     * @returns {number}
     */
    get int() {
        return this.readInt32();
    }
    ;
    /**
     * Read 32 bit integer.
     *
     * @returns {number}
     */
    get double() {
        return this.readInt32();
    }
    ;
    /**
     * Read 32 bit integer.
     *
     * @returns {number}
     */
    get int32() {
        return this.readInt32();
    }
    ;
    /**
     * Read 32 bit integer.
     *
     * @returns {number}
     */
    get long() {
        return this.readInt32();
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get uint() {
        return this.readInt32(true);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get udouble() {
        return this.readInt32(true);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get uint32() {
        return this.readInt32(true);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get ulong() {
        return this.readInt32(true);
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get intbe() {
        return this.readInt32(false, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get doublebe() {
        return this.readInt32(false, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get int32be() {
        return this.readInt32(false, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get longbe() {
        return this.readInt32(false, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get uintbe() {
        return this.readInt32(true, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get udoublebe() {
        return this.readInt32(true, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get uint32be() {
        return this.readInt32(true, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {number}
     */
    get ulongbe() {
        return this.readInt32(true, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get intle() {
        return this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get doublele() {
        return this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get int32le() {
        return this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get longle() {
        return this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get uintle() {
        return this.readInt32(true, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get udoublele() {
        return this.readInt32(true, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get uint32le() {
        return this.readInt32(true, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {number}
     */
    get ulongle() {
        return this.readInt32(true, "little");
    }
    ;
    //
    // #region float read
    //
    /**
     * Read float.
     *
     * @returns {number}
     */
    get float() {
        return this.readFloat();
    }
    ;
    /**
     * Read float.
     *
     * @returns {number}
     */
    get floatbe() {
        return this.readFloat("big");
    }
    ;
    /**
     * Read float.
     *
     * @returns {number}
     */
    get floatle() {
        return this.readFloat("little");
    }
    ;
    //
    // #region int64 reader
    //
    /**
     * Read signed 64 bit integer
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get int64() {
        return this.readInt64();
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get bigint() {
        return this.readInt64();
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get quad() {
        return this.readInt64();
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get uint64() {
        return this.readInt64(true);
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get ubigint() {
        return this.readInt64(true);
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get uquad() {
        return this.readInt64(true);
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get int64be() {
        return this.readInt64(false, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get bigintbe() {
        return this.readInt64(false, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get quadbe() {
        return this.readInt64(false, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get uint64be() {
        return this.readInt64(true, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get ubigintbe() {
        return this.readInt64(true, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get uquadbe() {
        return this.readInt64(true, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get int64le() {
        return this.readInt64(false, "little");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get bigintle() {
        return this.readInt64(false, "little");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get quadle() {
        return this.readInt64(false, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get uint64le() {
        return this.readInt64(true, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get ubigintle() {
        return this.readInt64(true, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    get uquadle() {
        return this.readInt64(true, "little");
    }
    ;
    //
    // #region doublefloat reader
    //
    /**
     * Read double float.
     *
     * @returns {number}
     */
    get doublefloat() {
        return this.readDoubleFloat();
    }
    ;
    /**
     * Read double float.
     *
     * @returns {number}
     */
    get dfloat() {
        return this.readDoubleFloat();
    }
    ;
    /**
     * Read double float.
     *
     * @returns {number}
     */
    get dfloatbe() {
        return this.readDoubleFloat("big");
    }
    ;
    /**
     * Read double float.
     *
     * @returns {number}
     */
    get doublefloatbe() {
        return this.readDoubleFloat("big");
    }
    ;
    /**
     * Read double float.
     *
     * @returns {number}
     */
    get dfloatle() {
        return this.readDoubleFloat("little");
    }
    ;
    /**
     * Read double float.
     *
     * @returns {number}
     */
    get doublefloatle() {
        return this.readDoubleFloat("little");
    }
    ;
    //
    // #region string reader
    //
    /**
    * Reads string, use options object for different types.
    *
    * @param {stringOptions} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - ascii, utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthReadSize"]?} options.lengthReadSize - for pascal strings. 1, 2 or 4 byte length read size
    * @param {stringOptions["stripNull"]?} options.stripNull - removes 0x00 characters
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for utf-16, utf-32, wide-pascal or double-wide-pascal
    * @returns {string}
    */
    string(options = this.strDefaults) {
        return this.readString(options);
    }
    ;
    /**
    * Reads string using setting from .strDefaults
    *
    * Default is ``utf-8``
    *
    * @returns {string}
    */
    get str() {
        return this.readString(this.strDefaults);
    }
    ;
    /**
    * Reads UTF-8 (C) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    utf8string(length, terminateValue, stripNull) {
        return this.string({ stringType: "utf-8", encoding: "utf-8", length: length, terminateValue: terminateValue, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-8 (C) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    cstring(length, terminateValue, stripNull) {
        return this.utf8string(length, terminateValue, stripNull);
    }
    ;
    /**
    * Reads ANSI string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    ansistring(length, terminateValue, stripNull) {
        return this.string({ stringType: "utf-8", encoding: "windows-1252", length: length, terminateValue: terminateValue, stripNull: stripNull });
    }
    ;
    /**
    * Reads latin1 string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    latin1string(length, terminateValue, stripNull) {
        return this.string({ stringType: "utf-8", encoding: "iso-8859-1", length: length, terminateValue: terminateValue, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    utf16string(length, terminateValue, stripNull, endian) {
        return this.string({ stringType: "utf-16", encoding: "utf-16", length: length, terminateValue: terminateValue, endian: endian, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    unistring(length, terminateValue, stripNull, endian) {
        return this.utf16string(length, terminateValue, stripNull, endian);
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in little endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    utf16stringle(length, terminateValue, stripNull) {
        return this.utf16string(length, terminateValue, stripNull, "little");
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in little endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    unistringle(length, terminateValue, stripNull) {
        return this.utf16stringle(length, terminateValue, stripNull);
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in big endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    utf16stringbe(length, terminateValue, stripNull) {
        return this.utf16string(length, terminateValue, stripNull, "big");
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in big endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    unistringbe(length, terminateValue, stripNull) {
        return this.utf16stringbe(length, terminateValue, stripNull);
    }
    ;
    /**
    * Reads UTF-32 (Unicode) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    utf32string(length, terminateValue, stripNull, endian) {
        return this.string({ stringType: "utf-32", encoding: "utf-32", length: length, terminateValue: terminateValue, endian: endian, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-32 (Unicode) string in little endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    utf32stringle(length, terminateValue, stripNull) {
        return this.utf32string(length, terminateValue, stripNull, "little");
    }
    ;
    /**
    * Reads UTF-32 (Unicode) string in big endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    utf32stringbe(length, terminateValue, stripNull) {
        return this.utf32string(length, terminateValue, stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    pstring(lengthReadSize, stripNull, endian) {
        return this.string({ stringType: "pascal", encoding: "utf-8", lengthReadSize: lengthReadSize, stripNull: stripNull, endian: endian });
    }
    ;
    /**
    * Reads Pascal string in little endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstringle(lengthReadSize, stripNull) {
        return this.pstring(lengthReadSize, stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string in big endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstringbe(lengthReadSize, stripNull) {
        return this.pstring(lengthReadSize, stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string 1 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    pstring1(stripNull, endian) {
        return this.pstring(1, stripNull, endian);
    }
    ;
    /**
    * Reads Pascal string 1 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstring1le(stripNull) {
        return this.pstring1(stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string 1 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstring1be(stripNull) {
        return this.pstring1(stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string 2 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    pstring2(stripNull, endian) {
        return this.pstring(2, stripNull, endian);
    }
    ;
    /**
    * Reads Pascal string 2 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstring2le(stripNull) {
        return this.pstring2(stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string 2 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstring2be(stripNull) {
        return this.pstring2(stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string 4 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    pstring4(stripNull, endian) {
        return this.pstring(4, stripNull, endian);
    }
    ;
    /**
    * Reads Pascal string 4 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstring4le(stripNull) {
        return this.pstring4(stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string 4 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    pstring4be(stripNull) {
        return this.pstring4(stripNull, "big");
    }
    ;
    /**
    * Reads Wide Pascal string.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    wpstring(lengthReadSize, stripNull, endian) {
        return this.string({ stringType: "wide-pascal", encoding: "utf-16", lengthReadSize: lengthReadSize, endian: endian, stripNull: stripNull });
    }
    ;
    /**
    * Reads Wide Pascal string 1 byte length read in little endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstringle(lengthReadSize, stripNull) {
        return this.wpstring(lengthReadSize, stripNull, "little");
    }
    ;
    /**
    * Reads Wide Pascal string 1 byte length read in big endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstringbe(lengthReadSize, stripNull) {
        return this.wpstring(lengthReadSize, stripNull, "big");
    }
    ;
    /**
    * Reads Wide Pascal string 1 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    wpstring1(stripNull, endian) {
        return this.wpstring(1, stripNull, endian);
    }
    ;
    /**
    * Reads Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstring1le(stripNull) {
        return this.wpstring1(stripNull, "little");
    }
    ;
    /**
    * Reads Wide Pascal string 1 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstring1be(stripNull) {
        return this.wpstring1(stripNull, "big");
    }
    ;
    /**
    * Reads Wide Pascal string 2 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    wpstring2(stripNull, endian) {
        return this.wpstring(2, stripNull, endian);
    }
    ;
    /**
    * Reads Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstring2le(stripNull) {
        return this.wpstring2(stripNull, "little");
    }
    ;
    /**
    * Reads Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstring2be(stripNull) {
        return this.wpstring2(stripNull, "big");
    }
    ;
    /**
    * Reads Wide Pascal string 4 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    wpstring4(stripNull, endian) {
        return this.wpstring(4, stripNull, endian);
    }
    ;
    /**
    * Reads Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstring4le(stripNull) {
        return this.wpstring4(stripNull, "little");
    }
    ;
    /**
    * Reads Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    wpstring4be(stripNull) {
        return this.wpstring4(stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    dwpstring(lengthReadSize, stripNull, endian) {
        return this.string({ stringType: "double-wide-pascal", encoding: "utf-32", lengthReadSize: lengthReadSize, stripNull: stripNull, endian: endian });
    }
    ;
    /**
    * Reads Double Wide Pascal string 1 byte length read in little endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstringle(lengthReadSize, stripNull) {
        return this.dwpstring(lengthReadSize, stripNull, "little");
    }
    ;
    /**
    * Reads Double Wide Pascal string 1 byte length read in big endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstringbe(lengthReadSize, stripNull) {
        return this.dwpstring(lengthReadSize, stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string 1 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    dwpstring1(stripNull, endian) {
        return this.dwpstring(1, stripNull, endian);
    }
    ;
    /**
    * Reads Double Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstring1le(stripNull) {
        return this.dwpstring1(stripNull, "little");
    }
    ;
    /**
    * Reads Double WidePascal string 1 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstring1be(stripNull) {
        return this.dwpstring1(stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string 2 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    dwpstring2(stripNull, endian) {
        return this.dwpstring(2, stripNull, endian);
    }
    ;
    /**
    * Reads Double Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstring2le(stripNull) {
        return this.dwpstring2(stripNull, "little");
    }
    ;
    /**
    * Reads Double Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstring2be(stripNull) {
        return this.dwpstring2(stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string 4 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {string}
    */
    dwpstring4(stripNull, endian) {
        return this.dwpstring(4, stripNull, endian);
    }
    ;
    /**
    * Reads Double Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstring4le(stripNull) {
        return this.dwpstring4(stripNull, "little");
    }
    ;
    /**
    * Reads Double Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {string}
    */
    dwpstring4be(stripNull) {
        return this.dwpstring4(stripNull, "big");
    }
    ;
}

/**
 * Binary writer, includes bitfields and strings.
 *
 * @param {DataType} input - File path or a `Buffer` or `Uint8Array`. Always found in .{@link data}
 * @param {BiOptions?} options - Any options to set at start
 * @param {BiOptions["byteOffset"]?} [options.byteOffset = 0] - Byte offset to start reader (default `0`)
 * @param {BiOptions["bitOffset"]?} [options.bitOffset = 0] - Bit offset (overrides {@link byteOffset}) (default `0`)
 * @param {BiOptions["endianness"]?} [options.endianness = "little"] - Endianness `big` or `little` (default `little`)
 * @param {BiOptions["strict"]?} [options.strict = true] - Strict mode: if `true` does not extend supplied array on outside read or write (default `true`)
 * @param {BiOptions["growthIncrement"]?} [options.growthIncrement = 1048576] - Amount of data to add when extending the buffer array when strict mode is false (default `1 MiB`)
 * @param {BiOptions["enforceBigInt"]?} [options.enforceBigInt = false] - 64 bit value reads will always return `bigint`. (default `false`)
 *
 * @since 2.0
 */
class BiWriter extends BiBase {
    constructor(input, options = {}) {
        options.byteOffset = options.byteOffset ?? 0;
        options.bitOffset = options.bitOffset ?? 0;
        options.endianness = options.endianness ?? "little";
        options.strict = options.strict ?? false;
        options.growthIncrement = options.growthIncrement ?? 0x100000;
        options.enforceBigInt = options.enforceBigInt ?? false;
        options.readOnly = options.readOnly ?? false;
        const { growthIncrement, } = options;
        if (input == undefined) {
            input = new Uint8Array(growthIncrement);
            console.warn(`BiWriter started without data. Creating Uint8Array with growthIncrement.`);
        }
        super(input, options);
    }
    ;
    //
    // #region Bit Aliases
    //
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    bit(value, bits, unsigned, endian) {
        return this.writeBit(value, bits, unsigned, endian);
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {endian} endian - ``big`` or ``little``
     * @returns {number}
     */
    ubit(value, bits, endian) {
        return this.writeBit(value, bits, true, endian);
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {number}
     */
    bitbe(value, bits, unsigned) {
        return this.bit(value, bits, unsigned, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @returns {number}
     */
    ubitbe(value, bits) {
        return this.bit(value, bits, true, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @returns {number}
     */
    ubitle(value, bits) {
        return this.bit(value, bits, true, "little");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {number}
     */
    bitle(value, bits, unsigned) {
        return this.bit(value, bits, unsigned, "little");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit1(value) {
        this.bit(value, 1);
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit1le(value) {
        this.bit(value, 1, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit1be(value) {
        this.bit(value, 1, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit1(value) {
        this.bit(value, 1, true);
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit1le(value) {
        this.bit(value, 1, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit1be(value) {
        this.bit(value, 1, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit2(value) {
        this.bit(value, 2);
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit2le(value) {
        this.bit(value, 2, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit2be(value) {
        this.bit(value, 2, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit2(value) {
        this.bit(value, 2, true);
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit2le(value) {
        this.bit(value, 2, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit2be(value) {
        this.bit(value, 2, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit3(value) {
        this.bit(value, 3);
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit3le(value) {
        this.bit(value, 3, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit3be(value) {
        this.bit(value, 3, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit3(value) {
        this.bit(value, 3, true);
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit3le(value) {
        this.bit(value, 3, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit3be(value) {
        this.bit(value, 3, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit4(value) {
        this.bit(value, 4);
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit4le(value) {
        this.bit(value, 4, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit4be(value) {
        this.bit(value, 4, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit4(value) {
        this.bit(value, 4, true);
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit4le(value) {
        this.bit(value, 4, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit4be(value) {
        this.bit(value, 4, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit5(value) {
        this.bit(value, 5);
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit5le(value) {
        this.bit(value, 5, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit5be(value) {
        this.bit(value, 5, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit5(value) {
        this.bit(value, 5, true);
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit5le(value) {
        this.bit(value, 5, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit5be(value) {
        this.bit(value, 5, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit6(value) {
        this.bit(value, 6);
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit6le(value) {
        this.bit(value, 6, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit6be(value) {
        this.bit(value, 6, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit6(value) {
        this.bit(value, 6, true);
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit6le(value) {
        this.bit(value, 6, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit6be(value) {
        this.bit(value, 6, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit7(value) {
        this.bit(value, 7);
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit7le(value) {
        this.bit(value, 7, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit7be(value) {
        this.bit(value, 7, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit7(value) {
        this.bit(value, 7, true);
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit7le(value) {
        this.bit(value, 7, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit7be(value) {
        this.bit(value, 7, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit8(value) {
        this.bit(value, 8);
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit8le(value) {
        this.bit(value, 8, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit8be(value) {
        this.bit(value, 8, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit8(value) {
        this.bit(value, 8, true);
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit8le(value) {
        this.bit(value, 8, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit8be(value) {
        this.bit(value, 8, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit9(value) {
        this.bit(value, 9);
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit9le(value) {
        this.bit(value, 9, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit9be(value) {
        this.bit(value, 9, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit9(value) {
        this.bit(value, 9, true);
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit9le(value) {
        this.bit(value, 9, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit9be(value) {
        this.bit(value, 9, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit10(value) {
        this.bit(value, 10);
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit10le(value) {
        this.bit(value, 10, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit10be(value) {
        this.bit(value, 10, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit10(value) {
        this.bit(value, 10, true);
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit10le(value) {
        this.bit(value, 10, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit10be(value) {
        this.bit(value, 10, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit11(value) {
        this.bit(value, 11);
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit11le(value) {
        this.bit(value, 11, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit11be(value) {
        this.bit(value, 11, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit11(value) {
        this.bit(value, 11, true);
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit11le(value) {
        this.bit(value, 11, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit11be(value) {
        this.bit(value, 11, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit12(value) {
        this.bit(value, 12);
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit12le(value) {
        this.bit(value, 12, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit12be(value) {
        this.bit(value, 12, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit12(value) {
        this.bit(value, 12, true);
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit12le(value) {
        this.bit(value, 12, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit12be(value) {
        this.bit(value, 12, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit13(value) {
        this.bit(value, 13);
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit13le(value) {
        this.bit(value, 13, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit13be(value) {
        this.bit(value, 13, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit13(value) {
        this.bit(value, 13, true);
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit13le(value) {
        this.bit(value, 13, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit13be(value) {
        this.bit(value, 13, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit14(value) {
        this.bit(value, 14);
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit14le(value) {
        this.bit(value, 14, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit14be(value) {
        this.bit(value, 14, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit14(value) {
        this.bit(value, 14, true);
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit14le(value) {
        this.bit(value, 14, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit14be(value) {
        this.bit(value, 14, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit15(value) {
        this.bit(value, 15);
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit15le(value) {
        this.bit(value, 15, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit15be(value) {
        this.bit(value, 15, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit15(value) {
        this.bit(value, 15, true);
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit15le(value) {
        this.bit(value, 15, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit15be(value) {
        this.bit(value, 15, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit16(value) {
        this.bit(value, 16);
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit16le(value) {
        this.bit(value, 16, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit16be(value) {
        this.bit(value, 16, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit16(value) {
        this.bit(value, 16, true);
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit16le(value) {
        this.bit(value, 16, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit16be(value) {
        this.bit(value, 16, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit17(value) {
        this.bit(value, 17);
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit17le(value) {
        this.bit(value, 17, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit17be(value) {
        this.bit(value, 17, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit17(value) {
        this.bit(value, 17, true);
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit17le(value) {
        this.bit(value, 17, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit17be(value) {
        this.bit(value, 17, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit18(value) {
        this.bit(value, 18);
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit18le(value) {
        this.bit(value, 18, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit18be(value) {
        this.bit(value, 18, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit18(value) {
        this.bit(value, 18, true);
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit18le(value) {
        this.bit(value, 18, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit18be(value) {
        this.bit(value, 18, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit19(value) {
        this.bit(value, 19);
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit19le(value) {
        this.bit(value, 19, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit19be(value) {
        this.bit(value, 19, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit19(value) {
        this.bit(value, 19, true);
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit19le(value) {
        this.bit(value, 19, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit19be(value) {
        this.bit(value, 19, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit20(value) {
        this.bit(value, 20);
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit20le(value) {
        this.bit(value, 20, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit20be(value) {
        this.bit(value, 20, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit20(value) {
        this.bit(value, 20, true);
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit20le(value) {
        this.bit(value, 20, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit20be(value) {
        this.bit(value, 20, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit21(value) {
        this.bit(value, 21);
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit21le(value) {
        this.bit(value, 21, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit21be(value) {
        this.bit(value, 21, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit21(value) {
        this.bit(value, 21, true);
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit21le(value) {
        this.bit(value, 21, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit21be(value) {
        this.bit(value, 21, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit22(value) {
        this.bit(value, 22);
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit22le(value) {
        this.bit(value, 22, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit22be(value) {
        this.bit(value, 22, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit22(value) {
        this.bit(value, 22, true);
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit22le(value) {
        this.bit(value, 22, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit22be(value) {
        this.bit(value, 22, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit23(value) {
        this.bit(value, 23);
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit23le(value) {
        this.bit(value, 23, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit23be(value) {
        this.bit(value, 23, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit23(value) {
        this.bit(value, 23, true);
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit23le(value) {
        this.bit(value, 23, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit23be(value) {
        this.bit(value, 23, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit24(value) {
        this.bit(value, 24);
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit24le(value) {
        this.bit(value, 24, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit24be(value) {
        this.bit(value, 24, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit24(value) {
        this.bit(value, 24, true);
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit24le(value) {
        this.bit(value, 24, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit24be(value) {
        this.bit(value, 24, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit25(value) {
        this.bit(value, 25);
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit25le(value) {
        this.bit(value, 25, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit25be(value) {
        this.bit(value, 25, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit25(value) {
        this.bit(value, 25, true);
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit25le(value) {
        this.bit(value, 25, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit25be(value) {
        this.bit(value, 25, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit26(value) {
        this.bit(value, 26);
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit26le(value) {
        this.bit(value, 26, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit26be(value) {
        this.bit(value, 26, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit26(value) {
        this.bit(value, 26, true);
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit26le(value) {
        this.bit(value, 26, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit26be(value) {
        this.bit(value, 26, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit27(value) {
        this.bit(value, 27);
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit27le(value) {
        this.bit(value, 27, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit27be(value) {
        this.bit(value, 27, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit27(value) {
        this.bit(value, 27, true);
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit27le(value) {
        this.bit(value, 27, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit27be(value) {
        this.bit(value, 27, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit28(value) {
        this.bit(value, 28);
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit28le(value) {
        this.bit(value, 28, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit28be(value) {
        this.bit(value, 28, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit28(value) {
        this.bit(value, 28, true);
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit28le(value) {
        this.bit(value, 28, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit28be(value) {
        this.bit(value, 28, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit29(value) {
        this.bit(value, 29);
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit29le(value) {
        this.bit(value, 29, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit29be(value) {
        this.bit(value, 29, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit29(value) {
        this.bit(value, 29, true);
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit29le(value) {
        this.bit(value, 29, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit29be(value) {
        this.bit(value, 29, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit30(value) {
        this.bit(value, 30);
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit30le(value) {
        this.bit(value, 30, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit30be(value) {
        this.bit(value, 30, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit30(value) {
        this.bit(value, 30, true);
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit30le(value) {
        this.bit(value, 30, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit30be(value) {
        this.bit(value, 30, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit31(value) {
        this.bit(value, 31);
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit31le(value) {
        this.bit(value, 31, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit31be(value) {
        this.bit(value, 31, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit31(value) {
        this.bit(value, 31, true);
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit31le(value) {
        this.bit(value, 31, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit31be(value) {
        this.bit(value, 31, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit32(value) {
        this.bit(value, 32);
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit32le(value) {
        this.bit(value, 32, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set bit32be(value) {
        this.bit(value, 32, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit32(value) {
        this.bit(value, 32, true);
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit32le(value) {
        this.bit(value, 32, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    set ubit32be(value) {
        this.bit(value, 32, true, "big");
    }
    ;
    //
    // #region byte write
    //
    /**
     * Write byte.
     *
     * @param {number} value - value as int
     */
    set byte(value) {
        this.writeByte(value);
    }
    ;
    /**
     * Write byte.
     *
     * @param {number} value - value as int
     */
    set int8(value) {
        this.writeByte(value);
    }
    ;
    /**
     * Write unsigned byte.
     *
     * @param {number} value - value as int
     */
    set uint8(value) {
        this.writeByte(value, true);
    }
    ;
    /**
     * Write unsigned byte.
     *
     * @param {number} value - value as int
     */
    set ubyte(value) {
        this.writeByte(value, true);
    }
    ;
    //
    // #region short writes
    //
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     */
    set int16(value) {
        this.writeInt16(value);
    }
    ;
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     */
    set short(value) {
        this.writeInt16(value);
    }
    ;
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     */
    set word(value) {
        this.writeInt16(value);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set uint16(value) {
        this.writeInt16(value, true);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set ushort(value) {
        this.writeInt16(value, true);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set uword(value) {
        this.writeInt16(value, true);
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    set int16be(value) {
        this.writeInt16(value, false, "big");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    set shortbe(value) {
        this.writeInt16(value, false, "big");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    set wordbe(value) {
        this.writeInt16(value, false, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set uint16be(value) {
        this.writeInt16(value, true, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set ushortbe(value) {
        this.writeInt16(value, true, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set uwordbe(value) {
        this.writeInt16(value, true, "big");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    set int16le(value) {
        this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    set shortle(value) {
        this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    set wordle(value) {
        this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set uint16le(value) {
        this.writeInt16(value, true, "little");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set ushortle(value) {
        this.writeInt16(value, true, "little");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    set uwordle(value) {
        this.writeInt16(value, true, "little");
    }
    ;
    //
    // #region half float
    //
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    set half(value) {
        this.writeHalfFloat(value);
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    set halffloat(value) {
        this.writeHalfFloat(value);
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    set halffloatbe(value) {
        this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    set halfbe(value) {
        this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    set halffloatle(value) {
        this.writeHalfFloat(value, "little");
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    set halfle(value) {
        this.writeHalfFloat(value, "little");
    }
    ;
    //
    // #region int32 write
    //
    /**
     * Write int32.
     *
     * @param {number} value - value as int
     */
    set int(value) {
        this.writeInt32(value);
    }
    ;
    /**
    * Write int32.
    *
    * @param {number} value - value as int
    */
    set int32(value) {
        this.writeInt32(value);
    }
    ;
    /**
     * Write int32.
     *
     * @param {number} value - value as int
     */
    set double(value) {
        this.writeInt32(value);
    }
    ;
    /**
     * Write int32.
     *
     * @param {number} value - value as int
     */
    set long(value) {
        this.writeInt32(value);
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set uint32(value) {
        this.writeInt32(value, true);
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set uint(value) {
        this.writeInt32(value, true);
    }
    ;
    /**
    * Write unsigned int32.
    *
    * @param {number} value - value as int
    */
    set udouble(value) {
        this.writeInt32(value, true);
    }
    ;
    /**
    * Write unsigned int32.
    *
    * @param {number} value - value as int
    */
    set ulong(value) {
        this.writeInt32(value, true);
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set int32le(value) {
        this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set intle(value) {
        this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set doublele(value) {
        this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set longle(value) {
        this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set uint32le(value) {
        this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set uintle(value) {
        this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set udoublele(value) {
        this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set ulongle(value) {
        this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set intbe(value) {
        this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set int32be(value) {
        this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set doublebe(value) {
        this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    set longbe(value) {
        this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set uint32be(value) {
        this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set uintbe(value) {
        this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set udoublebe(value) {
        this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    set ulongbe(value) {
        this.writeInt32(value, true, "big");
    }
    ;
    //
    // #region float write
    //
    /**
    * Write float.
    *
    * @param {number} value - value as int
    */
    set float(value) {
        this.writeFloat(value);
    }
    ;
    /**
     * Write float.
     *
     * @param {number} value - value as int
     */
    set floatle(value) {
        this.writeFloat(value, "little");
    }
    ;
    /**
    * Write float.
    *
    * @param {number} value - value as int
    */
    set floatbe(value) {
        this.writeFloat(value, "big");
    }
    ;
    //
    // #region int64 write
    //
    /**
     * Write 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set int64(value) {
        this.writeInt64(value);
    }
    ;
    /**
    * Write 64 bit integer.
    *
    * @param {BigValue} value - value as int
    */
    set quad(value) {
        this.writeInt64(value);
    }
    ;
    /**
     * Write 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set bigint(value) {
        this.writeInt64(value);
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set uint64(value) {
        this.writeInt64(value, true);
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set ubigint(value) {
        this.writeInt64(value, true);
    }
    ;
    /**
    * Write unsigned 64 bit integer.
    *
    * @param {BigValue} value - value as int
    */
    set uquad(value) {
        this.writeInt64(value, true);
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set int64le(value) {
        this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set bigintle(value) {
        this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set quadle(value) {
        this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set uint64le(value) {
        this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set ubigintle(value) {
        this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set uquadle(value) {
        this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set int64be(value) {
        this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set bigintbe(value) {
        this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set quadbe(value) {
        this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set uint64be(value) {
        this.writeInt64(value, true, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set ubigintbe(value) {
        this.writeInt64(value, true, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    set uquadbe(value) {
        this.writeInt64(value, true, "big");
    }
    ;
    //
    // #region doublefloat
    //
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    set doublefloat(value) {
        this.writeDoubleFloat(value);
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    set dfloat(value) {
        this.writeDoubleFloat(value);
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    set dfloatbe(value) {
        this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    set doublefloatbe(value) {
        this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    set dfloatle(value) {
        this.writeDoubleFloat(value, "little");
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    set doublefloatle(value) {
        this.writeDoubleFloat(value, "little");
    }
    ;
    //
    // #region string
    //
    /**
    * Writes string, use options object for different types.
    *
    * @param {string} string - text string
    * @param {stringOptions?} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - ascii, utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthWriteSize"]?} options.lengthWriteSize - for pascal strings. 1, 2 or 4 byte length write size
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for utf-16, utf-32, wide-pascal or double-wide-pascal
    */
    string(string, options = this.strDefaults) {
        return this.writeString(string, options);
    }
    ;
    /**
    * Writes string using setting from .strDefaults
    *
    * Default is ``utf-8``
    *
    * @param {string} string - text string
    */
    set str(string) {
        this.writeString(string, this.strDefaults);
    }
    ;
    /**
    * Writes UTF-8 (C) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    utf8string(string, length, terminateValue) {
        return this.string(string, { stringType: "utf-8", encoding: "utf-8", length: length, terminateValue: terminateValue });
    }
    ;
    /**
    * Writes UTF-8 (C) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    cstring(string, length, terminateValue) {
        return this.utf8string(string, length, terminateValue);
    }
    ;
    /**
    * Writes ANSI string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    ansistring(string, length, terminateValue) {
        return this.string(string, { stringType: "utf-8", encoding: "windows-1252", length: length, terminateValue: terminateValue });
    }
    ;
    /**
    * Writes latin1 string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    latin1string(string, length, terminateValue) {
        return this.string(string, { stringType: "utf-8", encoding: "iso-8859-1", length: length, terminateValue: terminateValue });
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["endian"]} endian - for wide-pascal and utf-16
    */
    utf16string(string, length, terminateValue, endian) {
        return this.string(string, { stringType: "utf-16", encoding: "utf-16", length: length, terminateValue: terminateValue, endian: endian });
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["endian"]} endian - for wide-pascal and utf-16
    */
    unistring(string, length, terminateValue, endian) {
        return this.utf16string(string, length, terminateValue, endian);
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    utf16stringle(string, length, terminateValue) {
        return this.unistring(string, length, terminateValue, "little");
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    unistringle(string, length, terminateValue) {
        return this.utf16stringle(string, length, terminateValue);
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    utf16stringbe(string, length, terminateValue) {
        return this.unistring(string, length, terminateValue, "big");
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    unistringbe(string, length, terminateValue) {
        return this.utf16stringbe(string, length, terminateValue);
    }
    ;
    /**
    * Writes UTF-32 (Unicode) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["endian"]} endian - for wide-pascal and utf-16
    */
    utf32string(string, length, terminateValue, endian) {
        return this.string(string, { stringType: "utf-32", encoding: "utf-32", length: length, terminateValue: terminateValue, endian: endian });
    }
    ;
    /**
    * Writes UTF-32 (Unicode) string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    utf32stringle(string, length, terminateValue) {
        return this.utf32string(string, length, terminateValue, "little");
    }
    ;
    /**
    * Writes UTF-32 (Unicode) string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    utf32stringbe(string, length, terminateValue) {
        return this.utf32string(string, length, terminateValue, "big");
    }
    ;
    /**
    * Writes Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["endian"]} endian - ``big`` or ``little`` for 2 or 4 byte length write size
    */
    pstring(string, lengthWriteSize, endian) {
        return this.string(string, { stringType: "pascal", encoding: "utf-8", lengthWriteSize: lengthWriteSize, endian: endian });
    }
    ;
    /**
    * Writes Pascal string 1 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little`` for 2 or 4 byte length write size
    */
    pstring1(string, endian) {
        return this.pstring(string, 1, endian);
    }
    ;
    /**
    * Writes Pascal string 1 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    pstring1le(string) {
        return this.pstring1(string, "little");
    }
    ;
    /**
    * Writes Pascal string 1 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    pstring1be(string) {
        return this.pstring1(string, "big");
    }
    ;
    /**
    * Writes Pascal string 2 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    pstring2(string, endian) {
        return this.pstring(string, 2, endian);
    }
    ;
    /**
    * Writes Pascal string 2 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    pstring2le(string) {
        return this.pstring2(string, "little");
    }
    ;
    /**
    * Writes Pascal string 2 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    pstring2be(string) {
        return this.pstring2(string, "big");
    }
    ;
    /**
    * Writes Pascal string 4 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    pstring4(string, endian) {
        return this.pstring(string, 4, endian);
    }
    ;
    /**
    * Writes Pascal string 4 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    pstring4le(string) {
        return this.pstring4(string, "little");
    }
    ;
    /**
    * Writes Pascal string 4 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    pstring4be(string) {
        return this.pstring4(string, "big");
    }
    ;
    /**
    * Writes Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    wpstring(string, lengthWriteSize, endian) {
        return this.string(string, { stringType: "wide-pascal", encoding: "utf-16", lengthWriteSize: lengthWriteSize, endian: endian });
    }
    ;
    /**
    * Writes Wide Pascal string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    wpstringle(string, lengthWriteSize) {
        return this.wpstring(string, lengthWriteSize, "little");
    }
    ;
    /**
    * Writes Wide Pascal string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    wpstringbe(string, lengthWriteSize) {
        return this.wpstring(string, lengthWriteSize, "big");
    }
    ;
    /**
    * Writes Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    wpstring1(string, endian) {
        return this.wpstring(string, 1, endian);
    }
    ;
    /**
    * Writes Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    wpstring1le(string) {
        return this.wpstring1(string, "little");
    }
    ;
    /**
    * Writes Wide Pascal string 1 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    wpstring1be(string) {
        return this.wpstring1(string, "big");
    }
    ;
    /**
    * Writes Wide Pascal string 2 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    wpstring2(string, endian) {
        return this.wpstring(string, 2, endian);
    }
    ;
    /**
    * Writes Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    wpstring2le(string) {
        return this.wpstring2(string, "little");
    }
    ;
    /**
    * Writes Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    wpstring2be(string) {
        return this.wpstring2(string, "big");
    }
    ;
    /**
    * Writes Wide Pascal string 4 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    wpstring4(string, endian) {
        return this.wpstring(string, 4, endian);
    }
    ;
    /**
    * Writes Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    wpstring4le(string) {
        return this.wpstring4(string, "little");
    }
    ;
    /**
    * Writes Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    wpstring4be(string) {
        return this.wpstring4(string, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    dwpstring(string, lengthWriteSize, endian) {
        return this.string(string, { stringType: "double-wide-pascal", encoding: "utf-32", lengthWriteSize: lengthWriteSize, endian: endian });
    }
    ;
    /**
    * Writes Double Wide Pascal string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    dwpstringle(string, lengthWriteSize) {
        return this.dwpstring(string, lengthWriteSize, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    dwpstringbe(string, lengthWriteSize) {
        return this.dwpstring(string, lengthWriteSize, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    dwpstring1(string, endian) {
        return this.dwpstring(string, 1, endian);
    }
    ;
    /**
    * Writes Double Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    dwpstring1le(string) {
        return this.dwpstring1(string, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string 1 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    dwpstring1be(string) {
        return this.dwpstring1(string, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string 2 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    dwpstring2(string, endian) {
        return this.dwpstring(string, 2, endian);
    }
    ;
    /**
    * Writes Double Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    dwpstring2le(string) {
        return this.dwpstring2(string, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    dwpstring2be(string) {
        return this.dwpstring2(string, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string 4 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    dwpstring4(string, endian) {
        return this.dwpstring(string, 4, endian);
    }
    ;
    /**
    * Writes Double Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    dwpstring4le(string) {
        return this.dwpstring4(string, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    dwpstring4be(string) {
        return this.dwpstring4(string, "big");
    }
    ;
}

/**
 * @file BiReaderAsync / Writer base for working in sync Buffers or full file reads. Node and Browser.
 */
var _a;
// #region Buffer Dummies
const buff2ByteDummy = new Uint8Array(2);
const view2ByteDummy = new DataView(buff2ByteDummy.buffer, buff2ByteDummy.byteOffset, buff2ByteDummy.byteLength);
const buff4ByteDummy = new Uint8Array(4);
const view4ByteDummy = new DataView(buff4ByteDummy.buffer, buff4ByteDummy.byteOffset, buff4ByteDummy.byteLength);
const buff8ByteDummy = new Uint8Array(8);
const view8ByteDummy = new DataView(buff8ByteDummy.buffer, buff8ByteDummy.byteOffset, buff8ByteDummy.byteLength);
/**
 * Base class for BiReader and BiWriter
 */
class BiBaseAsync {
    /**
     * File System
     */
    static fs;
    /**
     * Endianness of default read.
     * @type {endian}
     */
    endian = "little";
    /**
     * Current read byte location.
     */
    #offset = 0;
    /**
     * Current read byte's bit location. 0 - 7
     */
    #insetBit = 0;
    /**
     * Size in bytes of the current buffer.
     */
    size = 0;
    /**
     * Size in bits of the current buffer.
     */
    bitSize = 0;
    /**
     * Allows the buffer to extend reading or writing outside of current size
     */
    strict = false;
    /**
     * Console log a hexdump on error.
     */
    errorDump = false;
    /**
     * Master Buffer
     */
    #data = null;
    /**
     * DataView of master Buffer
     */
    #view = null;
    /**
     * When the data buffer needs to be extended while strict mode is ``false``, this will be the amount it extends.
     *
     * Otherwise it extends just the amount of the next written value.
     *
     * This can greatly speed up data writes when large files are being written.
     *
     * NOTE: Using ``BiWriterAsync.get`` or ``BiWriterAsync.return`` will now remove all data after the current write position. Use ``BiWriterAsync.data`` to get the full buffer instead.
     */
    growthIncrement = 1048576;
    /**
     * Open file handle
     */
    fd = null;
    /**
     * Current file path
     */
    filePath;
    /**
     * File write mode
     */
    fsMode = "r";
    /**
     * The settings that used when using the .str getter / setter
     */
    strDefaults = { stringType: "utf-8", terminateValue: 0x0 };
    /**
     * All int64 reads will return as bigint type
     */
    enforceBigInt = null;
    /**
     * Not using a file reader.
     */
    isMemoryMode = false;
    /**
     * If data can not be written to the buffer.
     */
    readOnly;
    /**
     * Get the current buffer data.
     *
     * Use async {@link getData} while in file mode!
     */
    get data() {
        return this.#data;
    }
    ;
    /**
     * Get the current buffer data.
     *
     * For use in file mode!
     */
    async getData() {
        return await this.get();
    }
    ;
    /**
     * Set the current buffer data.
     */
    set data(data) {
        if (this.isBufferOrUint8Array(data)) {
            this.#data = data;
            this.#updateView();
            this.size = this.#data.length;
            this.bitSize = this.size * 8;
        }
    }
    ;
    /**
     * If the buffer was extended and needs to be trimmed
     */
    wasExpanded = false;
    /**
     * Get the DataView of current buffer data.
     */
    get view() {
        return this.#view;
    }
    ;
    // ASYNC ONLY
    /**
     * array of loaded data chunks
     * @type {ReturnMapping<DataType>[]}
     */
    chunks = [];
    /**
     * Promises for data chunks
     */
    chunkPromises = [];
    /**
     * Edited data chunks
     */
    dirtyChunks = new Set();
    /**
     * The amount of data to "chunk" and read a time from the file
     *
     * When set to 0, reads whole file at once.
     */
    windowSize = 4096;
    /**
     * Data is finished loading
     */
    isFullyLoaded = false;
    /**
     * Array of all chunks to quickly load all parts
     */
    loadAllPromise = null;
    constructor(input, options = {}) {
        const { byteOffset, bitOffset, endianness, strict, growthIncrement, enforceBigInt, readOnly, windowSize, } = options;
        if (typeof strict != "boolean") {
            throw new TypeError("Strict mode must be true or false");
        }
        this.#offset = byteOffset;
        if ((bitOffset ?? 0) != 0) {
            this.#offset = Math.floor(byteOffset / 8);
            this.#insetBit = byteOffset % 8;
        }
        this.windowSize = windowSize;
        this.readOnly = !!readOnly;
        this.strict = this.readOnly ? true : strict;
        this.fsMode = this.readOnly ? 'r' : 'r+';
        this.enforceBigInt = !!enforceBigInt;
        if (!hasBigInt) {
            this.enforceBigInt = false;
        }
        this.growthIncrement = growthIncrement;
        if (typeof endianness != "string" || !(endianness == "big" || endianness == "little")) {
            throw new TypeError("Endian must be big or little");
        }
        this.endian = endianness;
        if (typeof input === 'string') {
            if (typeof Buffer === 'undefined') {
                throw new Error("Can't load file outside of Node.");
            }
            this.filePath = input;
            this.isMemoryMode = false;
        }
        else if (this.isBufferOrUint8Array(input)) {
            this.data = input;
            this.isMemoryMode = true;
            this.filePath = null;
            this.windowSize = 0;
            this.#initMemory();
        }
        else {
            throw new TypeError('Source must be a file path (string) or Uint8Array/Buffer');
        }
    }
    ;
    /**
     * Settings for when using .str
     *
     * @param {stringOptions} settings options to use with .str
     */
    set strSettings(settings) {
        this.strDefaults.encoding = settings.encoding;
        this.strDefaults.endian = settings.endian;
        this.strDefaults.length = settings.length;
        this.strDefaults.lengthReadSize = settings.lengthReadSize;
        this.strDefaults.lengthWriteSize = settings.lengthWriteSize;
        this.strDefaults.stringType = settings.stringType;
        this.strDefaults.stripNull = settings.stripNull;
        this.strDefaults.terminateValue = settings.terminateValue;
    }
    ;
    ///////////////////////////////
    // #region INTERNALS
    ///////////////////////////////
    /**
     * Checks if obj is an Uint8Array or a Buffer
     */
    isBufferOrUint8Array(obj) {
        return isBufferOrUint8Array(obj);
    }
    ;
    /**
     * Checks if obj is a Buffer
     */
    isBuffer(obj) {
        return isBuffer(obj);
    }
    ;
    /**
     * Checks if obj is an Uint8Array
     */
    isUint8Array(obj) {
        return isUint8Array(obj);
    }
    ;
    async #fileExists(filePath) {
        if (_a.fs == undefined) {
            return false;
        }
        try {
            await _a.fs.access(filePath, _a.fs.constants.F_OK);
            return true; // File exists
        }
        catch (error) {
            return false;
        }
    }
    ;
    /**
     * Internal update size
     *
     * run after setting data
     */
    async #updateSize() {
        if (this.isMemoryMode) {
            this.size = this.data.length;
            this.bitSize = this.size * 8;
            return;
        }
        if (typeof _a.fs === "undefined") {
            throw new Error("Can't load file outside Node.");
        }
        if (this.fd != null) {
            try {
                const stat = await this.fd.stat();
                this.size = stat.size;
                this.bitSize = this.size * 8;
            }
            catch (error) {
                throw new Error(error);
            }
        }
    }
    ;
    /**
     * Call this after everytime we set/replace `this.data`
     */
    #updateView() {
        if (this.#data) {
            this.#view = new DataView(this.#data.buffer, this.#data.byteOffset ?? 0, this.#data.byteLength);
        }
    }
    ;
    /**
     * `this.fd` must be null and not in memory mode
     */
    async #initFile() {
        if (this.isMemoryMode || this.fd != null) {
            return;
        }
        if (!(await this.#fileExists(this.filePath))) {
            await _a.fs.writeFile(this.filePath, "");
        }
        try {
            this.fd = await _a.fs.open(this.filePath, this.fsMode);
        }
        catch (error) {
            throw new Error(error);
        }
        await this.#updateSize();
        const numChunks = this.#getNumChunks();
        this.chunks = new Array(numChunks).fill(null);
        this.chunkPromises = new Array(numChunks).fill(null);
        if (this.windowSize == 0) {
            this.loadAllPromise = this.#preloadAllChunks();
        }
        else {
            this.loadAllPromise = Promise.resolve();
        }
    }
    ;
    /**
     * Not for file mode
     */
    #initMemory() {
        if (!this.isMemoryMode) {
            return;
        }
        if (this.isFullyLoaded) {
            return;
        }
        this.size = this.data.length;
        this.bitSize = this.size * 8;
        const numChunks = this.#getNumChunks();
        this.chunks = new Array(numChunks).fill(null);
        this.chunkPromises = new Array(numChunks).fill(null);
        this.isFullyLoaded = true;
        this.loadAllPromise = null;
    }
    ;
    /**
     * For when there is a full file read
     */
    #getChunkIndex(offset) {
        return this.windowSize === 0 ? 0 : Math.floor(offset / this.windowSize);
    }
    ;
    /**
     * For when there is a full file read
     */
    #getNumChunks() {
        return this.windowSize === 0 ? 1 : Math.ceil(this.size / this.windowSize);
    }
    ;
    /**
     * When the whole file is loaded at once
     */
    async #preloadAllChunks() {
        const promises = [];
        for (let i = 0; i < this.chunks.length; i++) {
            promises.push(this.#ensureChunkLoaded(i));
        }
        await Promise.all(promises);
        this.isFullyLoaded = true;
    }
    ;
    /**
     * Checks the chunk is loaded
     *
     * @param {number} chunkIndex
     */
    async #ensureChunkLoaded(chunkIndex) {
        if (this.windowSize === 0) {
            chunkIndex = 0;
        }
        if (chunkIndex >= this.chunks.length) {
            return null;
        }
        if (this.chunks[chunkIndex] !== null) {
            return this.chunks[chunkIndex];
        }
        if (this.isMemoryMode) {
            const start = chunkIndex * this.windowSize;
            const end = Math.min(start + this.windowSize, this.size);
            this.chunks[chunkIndex] = this.data.subarray(start, end);
            return this.chunks[chunkIndex];
        }
        if (this.chunkPromises[chunkIndex]) {
            return await this.chunkPromises[chunkIndex];
        }
        const promise = this.#performChunkLoad(chunkIndex);
        this.chunkPromises[chunkIndex] = promise;
        return await promise;
    }
    ;
    /**
     * Gets needed chunk
     *
     * @param {number} chunkIndex
     */
    async #performChunkLoad(chunkIndex) {
        const start = chunkIndex * this.windowSize;
        const length = Math.min(this.windowSize, this.size - start);
        const buffer = Buffer.alloc(length);
        await this.fd.read(buffer, 0, length, start);
        this.chunks[chunkIndex] = buffer;
        return buffer;
    }
    ;
    /**
     * Makes sure the needed size is loaded
     *
     * @param {number} offset
     * @param {number} length
     */
    async #ensureRangeLoaded(offset, length) {
        const needed = offset + length;
        if (needed > this.size) {
            if (this.strict || this.readOnly) {
                throw new Error(`Operation exceeds file size (${needed} > ${this.size})`);
            }
            await this.#confrimSize(needed);
        }
        const startChunk = this.#getChunkIndex(offset);
        const endChunk = this.#getChunkIndex(offset + length - 1);
        const promises = [];
        for (let i = startChunk; i <= endChunk && i < this.chunks.length; i++) {
            if (this.chunks[i] === null) {
                promises.push(this.#ensureChunkLoaded(i));
            }
        }
        await Promise.all(promises);
    }
    ;
    /**
     * Get bytes without changing offset
     *
     * @param {number} offset
     * @param {number} length
     */
    async #peekBytes(offset, length) {
        await this.open();
        if (length <= 0) {
            if (this.isMemoryMode) {
                if (this.isBuffer(this.data)) {
                    return Buffer.alloc(0);
                }
                else {
                    return new Uint8Array(0);
                }
            }
            else {
                return Buffer.alloc(0);
            }
        }
        await this.#ensureRangeLoaded(offset, length);
        var result;
        if (this.isMemoryMode) {
            return this.data.subarray(offset, offset + length);
        }
        else {
            result = Buffer.alloc(length);
        }
        let pos = offset;
        let writePos = 0;
        while (writePos < length) {
            const chunkIndex = this.#getChunkIndex(pos);
            const chunk = this.chunks[chunkIndex];
            const chunkOffset = pos % this.windowSize;
            const toCopy = Math.min(length - writePos, chunk.length - chunkOffset);
            result.set(chunk.subarray(chunkOffset, chunkOffset + toCopy), writePos);
            writePos += toCopy;
            pos += toCopy;
        }
        return result;
    }
    ;
    /**
     * write bytes internal
     *
     * @param {number} offset
     * @param {Uint8Array | Buffer} data
     */
    async #writeBytesAt(offset, data) {
        await this.open();
        if (data.length === 0) {
            return;
        }
        await this.#ensureRangeLoaded(offset, data.length);
        let pos = offset;
        let readPos = 0;
        if (this.isMemoryMode) {
            this.data.set(data, offset);
            return;
        }
        while (readPos < data.length) {
            const chunkIndex = this.#getChunkIndex(pos);
            const chunk = this.chunks[chunkIndex];
            const chunkOffset = pos % this.windowSize;
            const toCopy = Math.min(data.length - readPos, chunk.length - chunkOffset);
            const sub = data.subarray ? data.subarray(readPos, readPos + toCopy) : data.slice(readPos, readPos + toCopy);
            chunk.set(sub, chunkOffset);
            this.dirtyChunks.add(chunkIndex);
            readPos += toCopy;
            pos += toCopy;
        }
    }
    ;
    /**
     * Checks loaded size
     *
     * Will set `wasExpanded` if expanded
     *
     * @param {number} neededSize
     */
    async #confrimSize(neededSize) {
        // check if the current request fits in range
        if (neededSize <= this.size) {
            return;
        }
        var targetSize = neededSize;
        // now adjust the size if less to `growthIncrement` factor
        if (targetSize > this.size) {
            if (this.strict || this.readOnly) {
                this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
                throw new Error(`\x1b[33m[Strict mode]\x1b[0m: Reached end of data: ` + neededSize + " at " + this.#offset + " of " + this.size);
            }
            if (this.growthIncrement != 0) {
                this.wasExpanded = true;
                targetSize = Math.ceil(neededSize / this.growthIncrement) * this.growthIncrement;
            }
            await this.#extendArray(targetSize);
        }
    }
    ;
    /**
    * extends the data
    *
    * @param {number} targetSize
    */
    async #extendArray(targetSize) {
        await this.flush();
        if (this.isMemoryMode) {
            const toPadd = targetSize - this.size;
            if (isBuffer(this.#data)) {
                const paddbuffer = Buffer.alloc(toPadd);
                this.data = Buffer.concat([this.#data, paddbuffer]);
            }
            else {
                const newBuf = new Uint8Array(this.size + toPadd);
                newBuf.set(this.#data);
                this.data = newBuf;
            }
            this.size = targetSize;
            this.bitSize = this.size * 8;
            this.chunks = new Array(this.#getNumChunks()).fill(null);
            this.chunkPromises = new Array(this.#getNumChunks()).fill(null);
            this.dirtyChunks.clear();
        }
        else {
            await this.fd.truncate(targetSize);
            this.size = targetSize;
            this.bitSize = this.size * 8;
            const oldNum = this.chunks.length;
            const newNum = this.#getNumChunks();
            this.chunks.length = newNum;
            this.chunkPromises.length = newNum;
            for (let i = oldNum; i < newNum; i++) {
                this.chunks[i] = null;
                this.chunkPromises[i] = null;
            }
        }
    }
    ;
    /**
     * For updating file size
     *
     * @param {number} exactSize
     * @returns
     */
    async #setFileSize(exactSize) {
        if (exactSize === this.size) {
            return;
        }
        await this.flush();
        if (this.isMemoryMode) {
            const newData = this.data.subarray(0, exactSize);
            this.data = newData;
            this.size = exactSize;
            this.bitSize = this.size * 8;
            const newNum = this.#getNumChunks();
            this.chunks = new Array(newNum).fill(null);
            this.chunkPromises = new Array(newNum).fill(null);
            this.dirtyChunks.clear();
        }
        else {
            await this.fd.truncate(exactSize);
            this.size = exactSize;
            this.bitSize = this.size * 8;
            const oldNum = this.chunks.length;
            const newNum = this.#getNumChunks();
            this.chunks.length = newNum;
            this.chunkPromises.length = newNum;
            if (newNum < oldNum) {
                this.dirtyChunks = new Set([...this.dirtyChunks].filter(i => i < newNum));
            }
            else {
                for (let i = oldNum; i < newNum; i++) {
                    this.chunks[i] = null;
                    this.chunkPromises[i] = null;
                }
            }
        }
        //this.#invalidateFromChunk(0);
    }
    ;
    /**
     * removes a chunk
     *
     * @param {number} startChunk
     */
    #invalidateFromChunk(startChunk) {
        const from = Math.max(0, startChunk);
        for (let i = from; i < this.chunks.length; i++) {
            this.chunks[i] = null;
            this.chunkPromises[i] = null;
            this.dirtyChunks.delete(i);
        }
        // Extra safety for windowSize === 0
        if (this.windowSize === 0 && this.chunks.length > 0) {
            this.chunks[0] = null;
            this.chunkPromises[0] = null;
        }
    }
    ;
    /**
     * Pulls data back
     *
     * @param {number} insertOffset
     * @param {number} insertLen
     * @param {number} oldEnd
     * @param {boolean} consume
     */
    async #shiftTailForward(insertOffset, insertLen, oldEnd, consume = false) {
        if (insertLen <= 0) {
            return;
        }
        if (this.isMemoryMode) {
            const tailCopy = this.data.subarray(insertOffset, oldEnd);
            this.data.set(tailCopy, insertOffset + insertLen);
        }
        else {
            let readEnd = oldEnd;
            let writeEnd = oldEnd + insertLen;
            const buf = Buffer.alloc(Math.min(this.windowSize, this.size));
            while (readEnd > insertOffset) {
                const len = Math.min(this.windowSize, readEnd - insertOffset);
                const readStart = readEnd - len;
                const { bytesRead } = await this.fd.read(buf, 0, len, readStart);
                const writeStart = writeEnd - len;
                await this.fd.write(buf, 0, bytesRead, writeStart);
                readEnd = readStart;
                writeEnd = writeStart;
            }
        }
        if (consume) {
            this.#offset = insertOffset + insertLen;
            this.#insetBit = 0;
        }
        this.#invalidateFromChunk(this.#getChunkIndex(insertOffset + insertLen));
    }
    ;
    /**
     *
     * @param {number} removeOffset
     * @param {number} removeLen
     * @param {boolean} consume
     */
    async #shiftTailBackward(removeOffset, removeLen, consume = false) {
        if (removeLen <= 0) {
            return;
        }
        if (this.isMemoryMode) {
            const tailStart = removeOffset + removeLen;
            const tailCopy = this.data.subarray(tailStart, this.size);
            this.data.set(tailCopy, removeOffset);
        }
        else {
            const oldEnd = this.size;
            let readPos = Math.min(removeOffset + removeLen, oldEnd);
            let writePos = removeOffset;
            const buf = Buffer.alloc(Math.min(this.windowSize, this.size));
            while (readPos < oldEnd) {
                const len = Math.min(this.windowSize, oldEnd - readPos);
                const { bytesRead } = await this.fd.read(buf, 0, len, readPos);
                await this.fd.write(buf, 0, bytesRead, writePos);
                readPos += bytesRead;
                writePos += bytesRead;
            }
            if (writePos < oldEnd) {
                const zeroBuf = Buffer.alloc(oldEnd - writePos);
                await this.fd.write(zeroBuf, 0, zeroBuf.length, writePos);
            }
        }
        if (consume) {
            this.#offset = removeOffset;
            this.#insetBit = 0;
        }
        this.#invalidateFromChunk(this.#getChunkIndex(removeOffset));
    }
    ;
    async #updateOffsets(newOffset, trueBytes, trueBits) {
        if (newOffset < 0) {
            throw new RangeError('Offset cannot be negative');
        }
        if (newOffset > this.size) {
            if (this.strict || this.readOnly) {
                this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
                throw new Error(`\x1b[33m[Strict mode]\x1b[0m: Reached end of data: ` + newOffset + " at " + this.#offset + " of " + this.size);
            }
            await this.#confrimSize(newOffset);
        }
        this.#offset = trueBytes;
        // Adjust byte offset based on bit overflow
        this.#offset += Math.floor(trueBits / 8);
        // Adjust bit offset
        this.#insetBit = normalizeBitOffset(trueBits) % 8;
        // Ensure bit offset stays between 0-7
        this.#insetBit = Math.min(Math.max(this.#insetBit, 0), 7);
        // Ensure offset doesn't go negative
        this.#offset = Math.max(this.#offset, 0);
    }
    ;
    async #readBytes(length, consume = true) {
        await this.open();
        if (length <= 0) {
            return Buffer.alloc(0);
        }
        const offSave = this.#offset;
        var trueByte = this.#offset;
        const trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#offset = trueByte;
        const data = await this.#peekBytes(trueByte, length);
        if (consume) {
            this.#offset += length;
            this.#insetBit = 0;
        }
        else {
            this.#offset = offSave;
        }
        return data;
    }
    ;
    async #writeBytes(data, consume = true) {
        if (this.readOnly) {
            throw new Error('Cannot write to read-only file');
        }
        await this.open();
        if (data.length === 0) {
            return;
        }
        const offSave = this.#offset;
        var trueByte = this.#offset;
        const trueBit = this.#insetBit;
        if (trueBit != 0) {
            trueByte += 1;
        }
        this.#offset = trueByte;
        await this.#writeBytesAt(trueByte, data);
        if (consume) {
            this.#offset += data.length;
            this.#insetBit = 0;
        }
        else {
            this.#offset = offSave;
        }
    }
    ;
    ///////////////////////////////
    // #region FILE MODE
    ///////////////////////////////
    /**
     * Enables writing and expanding (changes strict AND readOnly)
     *
     * @param {boolean} mode - True to enable writing and expanding (changes strict AND readOnly)
     */
    async writeMode(mode = true) {
        if (mode) {
            this.strict = false;
            this.readOnly = false;
            this.fsMode = "r+";
        }
        else {
            this.strict = true;
            this.readOnly = true;
            this.fsMode = "r";
        }
        if (!this.isMemoryMode) {
            await this.close();
            await this.open();
        }
    }
    ;
    /**
     * Opens the file in `file` mode. Must be run before reading or writing.
     *
     * Can be used to pass new data to a loaded class, shifting to memory mode.
     */
    async open(data) {
        if (!this.isMemoryMode) {
            await this.#initFile();
        }
        else {
            if (this.isBufferOrUint8Array(data)) {
                this.data = data;
            }
            this.#initMemory();
        }
    }
    ;
    /**
     * commit data and removes it.
     */
    async close() {
        await this.open();
        if (!this.readOnly && this.dirtyChunks.size > 0) {
            await this.flush();
        }
        if (this.loadAllPromise && !this.isFullyLoaded) {
            await this.loadAllPromise;
        }
        if (this.isMemoryMode) {
            return this.data;
        }
        if (this.fd) {
            const data = await this.getData();
            await this.fd.close();
            this.fd = null;
            return data;
        }
    }
    ;
    /**
     * Write data buffer back to file
     */
    async commit() {
        if (this.readOnly || this.dirtyChunks.size === 0 || this.isMemoryMode || !this.fd) {
            return;
        }
        const promises = [...this.dirtyChunks].map(i => {
            const chunk = this.chunks[i];
            if (!chunk) {
                return null;
            }
            return this.fd.write(chunk, 0, chunk.length, Math.min(i * this.windowSize, this.size));
        }).filter(Boolean);
        await Promise.all(promises);
        this.dirtyChunks.clear();
    }
    ;
    /**
     * Write data buffer back to file
     */
    async flush() {
        if (this.fd) {
            await this.commit();
        }
    }
    ;
    /**
     * Renames the file you are working on.
     *
     * Must be full file path and file name.
     *
     * Keeps write / read position.
     *
     * Note: This is permanent and can't be undone.
     *
     * @param {string} newFilePath - New full file path and name.
     */
    async renameFile(newFilePath) {
        if (this.isMemoryMode) {
            return;
        }
        try {
            await this.close();
            this.fd = null;
            this.#data = null;
            this.#view = null;
            await _a.fs.rename(this.filePath, newFilePath);
        }
        catch (error) {
            throw new Error(error);
        }
        this.filePath = newFilePath;
        await this.open();
    }
    ;
    /**
     * Deletes the working file.
     *
     * Note: This is permanent and can't be undone.
     *
     * It doesn't send the file to the recycling bin for recovery.
     */
    async deleteFile() {
        if (this.isMemoryMode) {
            return;
        }
        if (this.readOnly) {
            throw new Error("Can't delete file in readOnly mode!");
        }
        // this.mode == "file"
        try {
            this.close();
            await _a.fs.unlink(this.filePath);
        }
        catch (error) {
            throw new Error(error);
        }
        this.filePath = null;
    }
    ;
    ///////////////////////////////
    // #region ENDIANNESS
    ///////////////////////////////
    /**
     *
     * Change endian, defaults to little.
     *
     * Can be changed at any time, doesn't loose position.
     *
     * @param {endian} endian - endianness ``big`` or ``little``
     */
    endianness(endian) {
        if (endian == undefined || typeof endian != "string") {
            throw new TypeError("Endian must be big or little");
        }
        if (endian != undefined && !(endian == "big" || endian == "little")) {
            throw new TypeError("Endian must be big or little");
        }
        this.endian = endian;
    }
    ;
    /**
     * Sets endian to big.
     */
    bigEndian() {
        this.endianness("big");
    }
    ;
    /**
     * Sets endian to big.
     */
    big() {
        this.endianness("big");
    }
    ;
    /**
     * Sets endian to big.
     */
    be() {
        this.endianness("big");
    }
    ;
    /**
     * Sets endian to little.
     */
    littleEndian() {
        this.endianness("little");
    }
    ;
    /**
     * Sets endian to little.
     */
    little() {
        this.endianness("little");
    }
    ;
    /**
     * Sets endian to little.
     */
    le() {
        this.endianness("little");
    }
    ;
    ///////////////////////////////
    // #region SIZE
    ///////////////////////////////
    /**
     * Size in bytes of the current buffer.
     *
     * @returns {number} size
     */
    get length() {
        return this.size;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     * @returns {number} size
     */
    get len() {
        return this.size;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get sizeBits() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     *  @returns {number} size
     */
    get fileSize() {
        return this.size;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     * @returns {number} size
     */
    get FileSize() {
        return this.size;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get lengthBits() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get fileBitSize() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bytes of the current buffer.
     *
     *  @returns {number} size
     */
    get fileSizeBits() {
        return this.bitSize;
    }
    ;
    /**
     * Size in bits of the current buffer.
     *
     * @returns {number} size
     */
    get lenBits() {
        return this.bitSize;
    }
    ;
    ///////////////////////////////
    // #region POSITION
    ///////////////////////////////
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get offset() {
        return this.#offset;
    }
    ;
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get getOffset() {
        return this.offset;
    }
    ;
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get tell() {
        return this.#offset;
    }
    ;
    /**
     * Get the current byte position.
     *
     * @returns {number} current byte position
     */
    get FTell() {
        return this.#offset;
    }
    ;
    /**
     * Get the current byte position;
     *
     * @returns {number} current byte position
     */
    get saveOffset() {
        return this.#offset;
    }
    ;
    /**
     * Get the current byte position;
     *
     * @returns {number} current byte position
     */
    get off() {
        return this.#offset;
    }
    ;
    /**
     * Get the current byte position;
     *
     * @returns {number} current byte position
     */
    get byteOffset() {
        return this.offset;
    }
    ;
    /**
     * Set the current byte position.
     *
     * same as {@link goto}
     */
    async setOffset(value) {
        await this.goto(value);
    }
    ;
    /**
     * Set the current byte position.
     *
     * same as {@link goto}
     */
    async setByteOffset(value) {
        await this.setOffset(value);
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get bitOffset() {
        return (this.#offset * 8) + this.#insetBit;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get offsetBits() {
        return this.bitOffset;
    }
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get getBitOffset() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get saveBitOffset() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get FTellBits() {
        return this.bitOffset;
    }
    ;
    /**
     * Get the current bit position (0-7).
     *
     * @returns {number} current bit position
     */
    get tellBits() {
        return this.#insetBit;
    }
    ;
    /**
     * Get the current bit position.
     *
     * @returns {number} current bit position
     */
    get offBits() {
        return this.bitOffset;
    }
    ;
    /**
     * Set the current bit position.
     */
    async setOffsetBits(value) {
        await this.goto(value - (value % 8), value % 8);
    }
    ;
    /**
     * Set the current bit position.
     */
    async setBitOffset(value) {
        await this.setOffsetBits(value);
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get insetBit() {
        return this.#insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get saveInsetBit() {
        return this.insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get inBit() {
        return this.insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get bitTell() {
        return this.insetBit;
    }
    ;
    /**
     * Get the current bit position with in the current byte (0-7).
     *
     * @returns {number} current bit position
     */
    get getInsetBit() {
        return this.insetBit;
    }
    ;
    /**
     * Set the current bit position with in the current byte (0-7).
     */
    async setInsetBit(value) {
        await this.goto(this.offset, value % 8);
    }
    ;
    /**
     * Size in bytes of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get remain() {
        return this.size - this.#offset;
    }
    ;
    /**
     * Size in bytes of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get remainBytes() {
        return this.remain;
    }
    ;
    /**
     * Size in bytes of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get FEoF() {
        return this.remainBytes;
    }
    ;
    /**
     * Size in bits of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get remainBits() {
        return (this.size * 8) - this.bitOffset;
    }
    ;
    /**
     * Size in bits of current read position to the end of the data.
     *
     * @returns {number} size
     */
    get FEoFBits() {
        return this.remainBits;
    }
    ;
    /**
     * Row line of the file (16 bytes per row).
     *
     * @returns {number} size
     */
    get getLine() {
        return Math.abs(Math.floor((this.#offset - 1) / 16));
    }
    ;
    /**
     * Row line of the file (16 bytes per row).
     *
     * @returns {number} size
     */
    get row() {
        return this.getLine;
    }
    ;
    ///////////////////////////////
    // #region FINISHING
    ///////////////////////////////
    /**
     * Returns current data.
     *
     * Note: Will remove all data after current position if ``growthIncrement`` was set.
     */
    async get() {
        await this.open();
        // Commit every pending change
        if (!this.readOnly && this.dirtyChunks.size > 0) {
            await this.flush();
        }
        // Make sure everything is loaded (works with windowSize=0 too)
        if (this.loadAllPromise && !this.isFullyLoaded) {
            await this.loadAllPromise;
        }
        if (this.growthIncrement != 0 && this.wasExpanded) {
            await this.trim();
        }
        if (this.isMemoryMode) {
            return this.#data;
        }
        const chunks = [];
        for (let i = 0; i < this.#getNumChunks(); i++) {
            const chunk = await this.#ensureChunkLoaded(i);
            chunks.push(chunk);
        }
        if (this.growthIncrement != 0) {
            return Buffer.concat(chunks).subarray(0, this.#offset);
        }
        return Buffer.concat(chunks);
    }
    ;
    /**
     * Returns current data.
     *
     * Note: Will remove all data after current position if ``growthIncrement`` was set and you expanded data past the end once.
     *
     * Use ``.data`` instead if you want the full buffer data.
     */
    async getFullBuffer() {
        return await this.get();
    }
    ;
    /**
     * Returns current data.
     *
     * Note: Will remove all data after current position if ``growthIncrement`` was set.
     */
    async return() {
        return await this.get();
    }
    ;
    /**
     * Removes data.
     *
     * Commits any changes to file when editing a file.
     */
    async end() {
        if (this.isMemoryMode) {
            this.#data = null;
            this.#view = null;
            return;
        }
        await this.commit();
        return;
    }
    ;
    /**
     * Removes data.
     *
     * Commits any changes to file when editing a file.
     */
    async done() {
        return await this.end();
    }
    ;
    /**
     * Removes data.
     *
     * Commits any changes to file when editing a file.
     */
    async finished() {
        return await this.end();
    }
    ;
    ///////////////////////////////
    // #region HEX DUMP
    ///////////////////////////////
    /**
    * Creates hex dump string. Will console log or return string if set in options.
    *
    * @param {object} options
    * @param {hexdumpOptions?} options - hex dump options
    * @param {hexdumpOptions["length"]} options.length - number of bytes to log, default ``192`` or end of data
    * @param {hexdumpOptions["startByte"]} options.startByte - byte to start dump (default ``0``)
    * @param {hexdumpOptions["suppressUnicode"]} options.suppressUnicode - Suppress unicode character preview for even columns.
    * @param {hexdumpOptions["returnString"]} options.returnString - Returns the hex dump string instead of logging it.
    */
    async hexdump(options = {}) {
        await this.open();
        const length = options?.length ?? 192;
        const startByte = options?.startByte ?? this.#offset;
        const endByte = Math.min(startByte + length, this.size);
        const newSize = endByte - startByte;
        if (startByte > this.size || endByte > this.size) {
            throw new RangeError("Hexdump amount is outside of data size: " + newSize + " of " + endByte);
        }
        const data = await this.#peekBytes(startByte, Math.min(endByte, this.size) - startByte);
        return _hexDump(data, options, startByte, endByte);
    }
    ;
    /**
     * Turn hexdump on error off (default on).
     */
    errorDumpOff() {
        this.errorDump = false;
    }
    ;
    /**
     * Turn hexdump on error on (default on).
     */
    errorDumpOn() {
        this.errorDump = true;
    }
    ;
    ///////////////////////////////
    // #region STRICT MODE
    ///////////////////////////////
    /**
     * Disallows extending data if position is outside of max size.
     */
    restrict() {
        this.strict = true;
    }
    ;
    /**
     * Allows extending data if position is outside of max size.
     */
    unrestrict() {
        this.strict = false;
    }
    ;
    ///////////////////////////////
    // #region   FIND 
    ///////////////////////////////
    /**
     * Searches for position of array of byte values from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {Uint8Array | Buffer | Array<number>} bytesToFind
     */
    async findBytes(bytesToFind) {
        if (Array.isArray(bytesToFind)) {
            bytesToFind = new Uint8Array(bytesToFind);
        }
        const data = await this.#peekBytes(0, this.size);
        if (this.isBuffer(data)) {
            var offset = data.subarray(this.#offset, this.size).indexOf(bytesToFind);
            if (offset == -1) {
                return -1;
            }
            return offset + this.#offset;
        }
        // data = Uint8Array
        for (let i = this.#offset; i <= this.size - bytesToFind.length; i++) {
            var match = true;
            for (let j = 0; j < bytesToFind.length; j++) {
                if (data[i + j] !== bytesToFind[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i; // Found the string, return the index
            }
        }
        return -1; // String not found
    }
    ;
    /**
     * Searches for byte position of string from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {string} string - String to search for.
     * @param {1|2|4} bytesPerChar - how many bytes each character should take up
     */
    async findString(string, bytesPerChar = 1) {
        const encoded = textEncode(string, bytesPerChar);
        return await this.findBytes(encoded);
    }
    ;
    #findNumber(data, value, bits, unsigned, endian = this.endian) {
        for (let z = this.#offset; z <= (this.size - (bits / 8)); z++) {
            var offsetInBits = 0;
            var currentValue = 0;
            for (var i = 0; i < bits;) {
                const remaining = bits - i;
                const bitOffset = offsetInBits & 7;
                const currentByte = data[z + (offsetInBits >> 3)];
                const read = Math.min(remaining, 8 - bitOffset);
                if (endian == "big") {
                    let mask = ~(0xFF << read);
                    let readBits = (currentByte >> (8 - read - bitOffset)) & mask;
                    currentValue <<= read;
                    currentValue |= readBits;
                }
                else {
                    let mask = ~(0xFF << read);
                    let readBits = (currentByte >> bitOffset) & mask;
                    currentValue |= readBits << i;
                }
                offsetInBits += read;
                i += read;
            }
            if (unsigned == true || bits <= 7) {
                currentValue = currentValue >>> 0;
            }
            else {
                if (currentValue & (1 << (bits - 1))) {
                    currentValue |= -1 ^ ((1 << bits) - 1);
                }
            }
            if (currentValue === value) {
                return z - this.#offset; // Found the byte, return the index from current
            }
        }
        return -1; // number not found
    }
    /**
     * Searches for byte value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findByte(value, unsigned = true, endian = this.endian) {
        const data = await this.#peekBytes(0, this.size);
        return this.#findNumber(data, value, 8, unsigned, endian);
    }
    ;
    /**
     * Searches for short value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findShort(value, unsigned = true, endian = this.endian) {
        const data = await this.#peekBytes(0, this.size);
        return this.#findNumber(data, value, 16, unsigned, endian);
    }
    ;
    /**
     * Searches for integer value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findInt(value, unsigned = true, endian = this.endian) {
        const data = await this.#peekBytes(0, this.size);
        return this.#findNumber(data, value, 32, unsigned, endian);
    }
    ;
    /**
     * Searches for 64 bit value (can be signed or unsigned) position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {BigValue} value - Number to search for.
     * @param {boolean} unsigned - If the number is unsigned (default true)
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findInt64(value, unsigned = true, endian = this.endian) {
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        const data = await this.#peekBytes(0, this.size);
        for (let z = this.#offset; z <= (this.size - 8); z++) {
            var currentValue = BigInt(0);
            if (endian == "little") {
                for (let i = 0; i < 8; i++) {
                    currentValue = currentValue | BigInt((data[z + i] & 0xFF)) << BigInt(8 * i);
                }
                if (unsigned == undefined || unsigned == false) {
                    if (currentValue & (BigInt(1) << BigInt(63))) {
                        currentValue -= BigInt(1) << BigInt(64);
                    }
                }
            }
            else {
                for (let i = 0; i < 8; i++) {
                    currentValue = (currentValue << BigInt(8)) | BigInt((data[z + i] & 0xFF));
                }
                if (unsigned == undefined || unsigned == false) {
                    if (currentValue & (BigInt(1) << BigInt(63))) {
                        currentValue -= BigInt(1) << BigInt(64);
                    }
                }
            }
            if (currentValue == BigInt(value)) {
                return z;
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for half float value position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findHalfFloat(value, endian = this.endian) {
        const data = await this.#peekBytes(0, this.size);
        for (let z = this.#offset; z <= (this.size - 2); z++) {
            var currentValue = 0;
            if (endian == "little") {
                currentValue = ((data[z + 1] & 0xFFFF) << 8) | (data[z] & 0xFFFF);
            }
            else {
                currentValue = ((data[z] & 0xFFFF) << 8) | (data[z + 1] & 0xFFFF);
            }
            const sign = (currentValue & 0x8000) >> 15;
            const exponent = (currentValue & 0x7C00) >> 10;
            const fraction = currentValue & 0x03FF;
            var floatValue;
            if (exponent === 0) {
                if (fraction === 0) {
                    floatValue = (sign === 0) ? 0 : -0; // +/-0
                }
                else {
                    // Denormalized number
                    floatValue = (sign === 0 ? 1 : -1) * Math.pow(2, -14) * (fraction / 0x0400);
                }
            }
            else if (exponent === 0x1F) {
                if (fraction === 0) {
                    floatValue = (sign === 0) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
                }
                else {
                    floatValue = Number.NaN;
                }
            }
            else {
                // Normalized number
                floatValue = (sign === 0 ? 1 : -1) * Math.pow(2, exponent - 15) * (1 + fraction / 0x0400);
            }
            if (floatValue === value) {
                return z; // Found the number, return the index
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for float value position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findFloat(value, endian = this.endian) {
        const data = await this.#peekBytes(0, this.size);
        for (let z = this.#offset; z <= (this.size - 4); z++) {
            var currentValue = 0;
            if (endian == "little") {
                currentValue = ((data[z + 3] & 0xFF) << 24) |
                    ((data[z + 2] & 0xFF) << 16) |
                    ((data[z + 1] & 0xFF) << 8) |
                    (data[z] & 0xFF);
            }
            else {
                currentValue = ((data[z] & 0xFF) << 24) |
                    ((data[z + 1] & 0xFF) << 16) |
                    ((data[z + 2] & 0xFF) << 8) |
                    (data[z + 3] & 0xFF);
            }
            const isNegative = (currentValue & 0x80000000) !== 0 ? 1 : 0;
            // Extract the exponent and fraction parts
            const exponent = (currentValue >> 23) & 0xFF;
            const fraction = currentValue & 0x7FFFFF;
            // Calculate the float value
            var floatValue;
            if (exponent === 0) {
                // Denormalized number (exponent is 0)
                floatValue = Math.pow(-1, isNegative) * Math.pow(2, -126) * (fraction / Math.pow(2, 23));
            }
            else if (exponent === 0xFF) {
                // Infinity or NaN (exponent is 255)
                floatValue = fraction === 0 ? (isNegative ? Number.NEGATIVE_INFINITY : Number.POSITIVE_INFINITY) : Number.NaN;
            }
            else {
                // Normalized number
                floatValue = Math.pow(-1, isNegative) * Math.pow(2, exponent - 127) * (1 + fraction / Math.pow(2, 23));
            }
            if (floatValue === value) {
                return z; // Found the number, return the index
            }
        }
        return -1; // number not found
    }
    ;
    /**
     * Searches for double float value position from current read position.
     *
     * Returns -1 if not found.
     *
     * Does not change current read position.
     *
     * @param {number} value - Number to search for.
     * @param {endian} endian - endianness of value (default set endian).
     */
    async findDoubleFloat(value, endian = this.endian) {
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        const data = await this.#peekBytes(0, this.size);
        for (let z = this.#offset; z <= (this.size - 8); z++) {
            var currentValue = BigInt(0);
            if (endian == "little") {
                for (let i = 0; i < 8; i++) {
                    currentValue = currentValue | BigInt((data[z + i] & 0xFF)) << BigInt(8 * i);
                }
            }
            else {
                for (let i = 0; i < 8; i++) {
                    currentValue = (currentValue << BigInt(8)) | BigInt((data[z + i] & 0xFF));
                }
            }
            const sign = (currentValue & BigInt("9223372036854775808")) >> BigInt(63);
            const exponent = Number((currentValue & BigInt("9218868437227405312")) >> BigInt(52)) - 1023;
            const fraction = Number(currentValue & BigInt("4503599627370495")) / Math.pow(2, 52);
            var floatValue;
            if (exponent == -1023) {
                if (fraction == 0) {
                    floatValue = (sign == BigInt(0)) ? 0 : -0; // +/-0
                }
                else {
                    // Denormalized number
                    floatValue = (sign == BigInt(0) ? 1 : -1) * Math.pow(2, -1022) * fraction;
                }
            }
            else if (exponent == 1024) {
                if (fraction == 0) {
                    floatValue = (sign == BigInt(0)) ? Number.POSITIVE_INFINITY : Number.NEGATIVE_INFINITY;
                }
                else {
                    floatValue = Number.NaN;
                }
            }
            else {
                // Normalized number
                floatValue = (sign == BigInt(0) ? 1 : -1) * Math.pow(2, exponent) * (1 + fraction);
            }
            if (floatValue == value) {
                return z;
            }
        }
        return -1; // number not found
    }
    ;
    ///////////////////////////////
    // #region MOVE TO
    ///////////////////////////////
    /**
     * Aligns current byte position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} number - Byte to align
     */
    async align(number) {
        const a = this.#offset % number;
        if (a) {
            await this.skip(number - a);
        }
    }
    ;
    /**
     * Reverse aligns current byte position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} number - Byte to align
     */
    async alignRev(number) {
        const a = this.#offset % number;
        if (a) {
            await this.skip(a * -1);
        }
    }
    ;
    /**
     * Offset current byte or bit position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} bytes - Bytes to skip
     * @param {number} bits - Bits to skip
     */
    async skip(bytes = 0, bits = 0) {
        await this.open();
        var newOffset = ((bytes + this.#offset) + Math.ceil((this.#insetBit + bits) / 8));
        if (bits && bits < 0) {
            newOffset = Math.floor((((bytes + this.#offset) * 8) + this.#insetBit + bits) / 8);
        }
        await this.#updateOffsets(newOffset, bytes, bits);
    }
    ;
    /**
    * Offset current byte or bit position.
    *
    * Note: Will extend array if strict mode is off and outside of max size.
    *
    * @param {number} bytes - Bytes to skip
    * @param {number} bits - Bits to skip
    */
    async jump(bytes, bits) {
        await this.skip(bytes, bits);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    async FSeek(byte, bit) {
        await this.goto(byte, bit);
    }
    ;
    /**
     * Offset current byte or bit position.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} bytes - Bytes to skip
     * @param {number} bits - Bits to skip
     */
    async seek(bytes, bits) {
        await this.skip(bytes, bits);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    async goto(byte = 0, bit = 0) {
        await this.open();
        var newOffset = byte + Math.ceil(bit / 8);
        await this.#updateOffsets(newOffset, byte, bit);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    async pointer(byte, bit) {
        await this.goto(byte, bit);
    }
    ;
    /**
     * Change position directly to address.
     *
     * Note: Will extend array if strict mode is off and outside of max size.
     *
     * @param {number} byte - byte to set to
     * @param {number} bit - bit to set to
     */
    async warp(byte, bit) {
        await this.goto(byte, bit);
    }
    ;
    /**
     * Set byte and bit position to start of data.
     */
    rewind() {
        this.#offset = 0;
        this.#insetBit = 0;
    }
    ;
    /**
     * Set byte and bit position to start of data.
     */
    gotoStart() {
        this.rewind();
    }
    ;
    /**
     * Set current byte and bit position to end of data.
     */
    last() {
        this.#offset = this.size;
        this.#insetBit = 0;
    }
    ;
    /**
     * Set current byte and bit position to end of data.
     */
    gotoEnd() {
        this.last();
    }
    ;
    /**
     * Set byte and bit position to start of data.
     */
    EoF() {
        this.last();
    }
    ;
    ///////////////////////////////
    // #region REMOVE
    ///////////////////////////////
    /**
     * Deletes part of data from start to current byte position unless supplied, returns removed.
     *
     * Note: Errors in strict mode.
     *
     * @param {number} startOffset - Start location (default 0)
     * @param {number} endOffset - End location (default current position)
     * @param {boolean} consume - Move position to end of removed data (default false)
     */
    async delete(startOffset = 0, endOffset = this.#offset, consume = false) {
        if (this.readOnly || this.strict) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("\x1b[33m[Strict mode]\x1b[0m: Can not remove data in strict mode: endOffset " + endOffset + " of " + this.size);
        }
        await this.open();
        startOffset = Math.abs(startOffset);
        const removeLen = endOffset - startOffset;
        if (startOffset < 0 || endOffset > this.size) {
            throw new RangeError('Remove range out of bounds');
        }
        if (removeLen <= 0) {
            if (this.isMemoryMode) {
                if (this.isBuffer(this.data)) {
                    return Buffer.alloc(0);
                }
                else {
                    return new Uint8Array(0);
                }
            }
            else {
                return Buffer.alloc(0);
            }
        }
        if (!this.readOnly && this.dirtyChunks.size > 0) {
            await this.flush();
        }
        const removed = await this.#peekBytes(startOffset, removeLen);
        await this.#shiftTailBackward(startOffset, removeLen, consume);
        const newSize = this.size - removeLen;
        await this.#setFileSize(newSize);
        const startChunk = this.#getChunkIndex(startOffset);
        this.#invalidateFromChunk(startChunk);
        return removed;
    }
    ;
    /**
     * Deletes part of data from current byte position to end, returns removed.
     *
     * Note: Errors in strict mode.
     */
    async clip() {
        return await this.delete(this.#offset, this.size, false);
    }
    ;
    /**
     * Deletes part of data from current byte position to end, returns removed.
     *
     * Note: Errors in strict mode.
     */
    async trim() {
        return await this.delete(this.#offset, this.size, false);
    }
    ;
    /**
     * Deletes part of data from current byte position to supplied length, returns removed.
     *
     * Note: Errors in strict mode.
     *
     * @param {number} length - Length of data in bytes to remove
     * @param {boolean} consume - Move position to end of removed data (default false)
     */
    async crop(length = 0, consume = false) {
        return await this.delete(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Deletes part of data from current position to supplied length, returns removed.
     *
     * Note: Only works in strict mode.
     *
     * @param {number} length - Length of data in bytes to remove
     * @param {boolean} consume - Move position to end of removed data (default false)
     */
    async drop(length = 0, consume = false) {
        return await this.delete(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Replaces data in data.
     *
     * Note: Errors on strict mode.
     *
     * @param {Uint8Array | Buffer} data - ``Uint8Array`` or ``Buffer`` to replace in data
     * @param {number} offset - Offset to add it at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default false)
     */
    async replace(data, offset = this.#offset, consume = false) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't replace data in readOnly mode!");
        }
        await this.open();
        if (this.isMemoryMode) {
            if (this.isBuffer(data)) {
                if (this.isUint8Array(this.data)) {
                    // source is Uint8Array
                    data = new Uint8Array(data);
                }
            }
            else {
                // input is Uint8Array
                if (this.isBuffer(this.data)) {
                    // source is Buffer
                    data = Buffer.from(data);
                }
            }
        }
        else {
            if (!this.isBuffer(data)) {
                data = Buffer.from(data);
            }
        }
        const insertLen = data.length ?? 0;
        if (insertLen === 0) {
            return;
        }
        if (offset + insertLen > this.size) {
            if (this.strict || this.readOnly) {
                throw new Error('Growing requires strict: false');
            }
            await this.#confrimSize(offset + insertLen);
        }
        //if (!this.readOnly && this.dirtyChunks.size > 0) {
        //    await this.flush();
        //}
        const savedOffset = this.#offset;
        const savedBitOffset = this.#insetBit;
        this.#offset = offset;
        this.#insetBit = 0;
        await this.#writeBytes(data, consume);
        //if (offset + insertLen < this.size) {
        //    const tailStartChunk = this.#getChunkIndex(offset + insertLen);
        //    
        //    this.#invalidateFromChunk(tailStartChunk);
        //}
        if (!consume) {
            this.#offset = savedOffset;
            this.#insetBit = savedBitOffset;
        }
    }
    ;
    /**
     * Replaces data in data.
     *
     * Note: Errors on strict mode.
     *
     * @param {Uint8Array | Buffer} data - ``Uint8Array`` or ``Buffer`` to replace in data
     * @param {number} offset - Offset to add it at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default false)
     */
    async overwrite(data, offset = this.#offset, consume = false) {
        return await this.replace(data, offset, consume);
    }
    ;
    ///////////////////////////////
    // #region  COPY OUT
    ///////////////////////////////
    /**
     * Returns part of data from current byte position to end of data unless supplied.
     *
     * @param {number} startOffset - Start location (default current position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move position to end of lifted data (default false)
     * @param {number} fillValue - Byte value to to fill returned data (does NOT fill unless supplied)
     */
    async fill(startOffset = this.#offset, endOffset = this.size, consume = false, fillValue) {
        if (this.readOnly && fillValue != undefined) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't remove data in readOnly mode!");
        }
        await this.open();
        if (startOffset < 0 || endOffset > this.size) {
            throw new RangeError('Remove range out of bounds');
        }
        const removeLen = endOffset - startOffset;
        if (removeLen <= 0) {
            if (this.isMemoryMode) {
                if (this.isBuffer(this.data)) {
                    return Buffer.alloc(0);
                }
                else {
                    return new Uint8Array(0);
                }
            }
            else {
                return Buffer.alloc(0);
            }
        }
        if (endOffset > this.size && this.strict) {
            throw new Error('Cannot extend data while in strict mode. Use unrestrict() to enable.');
        }
        if (fillValue != undefined) {
            var replacement;
            if (this.isMemoryMode) {
                if (this.isBuffer(this.data)) {
                    replacement = Buffer.alloc(removeLen, fillValue);
                }
                else {
                    replacement = new Uint8Array(removeLen).fill(fillValue & 0xff);
                }
            }
            else {
                replacement = Buffer.alloc(removeLen, fillValue);
            }
            const offsetSaver = this.#offset;
            const offsetBitSaver = this.#insetBit;
            await this.#writeBytes(replacement, consume);
            if (!consume) {
                this.#offset = offsetSaver;
                this.#insetBit = offsetBitSaver;
            }
        }
        else {
            const dataRemoved = await this.#peekBytes(startOffset, removeLen);
            if (consume) {
                this.#offset = endOffset;
                this.#insetBit = 0;
            }
            return dataRemoved;
        }
    }
    ;
    /**
     * Returns part of data from current byte position to end of data unless supplied.
     *
     * @param {number} startOffset - Start location (default current position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move position to end of lifted data (default false)
     * @param {number} fillValue - Byte value to to fill returned data (does NOT fill unless supplied)
     */
    async lift(startOffset = this.#offset, endOffset = this.size, consume = false, fillValue) {
        return await this.fill(startOffset, endOffset, consume, fillValue);
    }
    ;
    /**
     * Returns part of data from current byte position to end of data unless supplied.
     *
     * @param {number} startOffset - Start location (default current position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move position to end of lifted data (default false)
     */
    async subarray(startOffset = this.#offset, endOffset = this.size, consume = false) {
        return await this.fill(startOffset, endOffset, consume);
    }
    /**
     * Extract data from current position to length supplied.
     *
     * Note: Does not affect supplied data.
     *
     * @param {number} length - Length of data in bytes to copy from current offset
     * @param {number} consume - Moves offset to end of length
     */
    async extract(length = 0, consume = false) {
        return await this.fill(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Extract data from current position to length supplied.
     *
     * Note: Does not affect supplied data.
     *
     * @param {number} length - Length of data in bytes to copy from current offset
     * @param {number} consume - Moves offset to end of length
     */
    async slice(length = 0, consume = false) {
        return await this.fill(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Extract data from current position to length supplied.
     *
     * Note: Does not affect supplied data.
     *
     * @param {number} length - Length of data in bytes to copy from current offset
     * @param {number} consume - Moves offset to end of length
     */
    async wrap(length = 0, consume = false) {
        return await this.fill(this.#offset, this.#offset + length, consume);
    }
    ;
    ///////////////////////////////
    // #region   INSERT
    ///////////////////////////////
    /**
     * Inserts data into data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {number} offset - Byte position to add at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default true)
     */
    async insert(data, offset = this.#offset, consume = true) {
        if (this.readOnly || this.strict) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error(`\x1b[33m[Strict mode]\x1b[0m: Can not insert data in strict mode. Use unrestrict() to enable.`);
        }
        if (!this.strict) {
            if (offset < 0 || offset > this.size) {
                throw new RangeError('Insert offset out of bounds');
            }
        }
        await this.open();
        if (this.isMemoryMode) {
            if (this.isBuffer(data)) {
                if (this.isUint8Array(this.data)) {
                    // source is Uint8Array
                    data = new Uint8Array(data);
                }
            }
            else {
                // input is Uint8Array
                if (this.isBuffer(this.data)) {
                    // source is Buffer
                    data = Buffer.from(data);
                }
            }
        }
        else {
            if (!this.isBuffer(data)) {
                data = Buffer.from(data);
            }
        }
        const insertLen = data.length ?? 0;
        if (insertLen === 0) {
            return;
        }
        const oldSize = this.size;
        const newSize = oldSize + insertLen;
        if (this.strict || this.readOnly) {
            throw new Error('Growing requires strict: false');
        }
        await this.#confrimSize(newSize);
        await this.flush();
        await this.#shiftTailForward(offset, insertLen, oldSize, false);
        const savedOffset = this.#offset;
        const savedBitOffset = this.#insetBit;
        this.#offset = offset;
        this.#insetBit = 0;
        await this.#writeBytes(data, consume);
        if (!consume) {
            this.#offset = savedOffset;
            this.#insetBit = savedBitOffset;
        }
    }
    ;
    /**
     * Inserts data into data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {number} offset - Byte position to add at (defaults to current position)
     * @param {boolean} consume - Move current byte position to end of data (default true)
     */
    async place(data, offset = this.#offset, consume = true) {
        return await this.insert(data, offset, consume);
    }
    ;
    /**
     * Adds data to start of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    async unshift(data, consume = false) {
        return await this.insert(data, 0, consume);
    }
    ;
    /**
     * Adds data to start of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    async prepend(data, consume = false) {
        return await this.unshift(data, consume);
    }
    ;
    /**
     * Adds data to end of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    async push(data, consume = false) {
        return await this.insert(data, this.size, consume);
    }
    ;
    /**
     * Adds data to end of supplied data.
     *
     * Note: Errors on strict mode.
     *
     * @param {ReturnMapping<DataType>} data - ``Uint8Array`` or ``Buffer`` to add to data
     * @param {boolean} consume - Move current write position to end of data (default false)
     */
    async append(data, consume = false) {
        return await this.push(data, consume);
    }
    ;
    ///////////////////////////////
    // #region  MATH 
    ///////////////////////////////
    /**
     * XOR data.
     *
     * @param {number|string|Uint8Array|Buffer} xorKey - Value, string or array to XOR
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async xor(xorKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof xorKey == "string") {
            xorKey = new TextEncoder().encode(xorKey);
        }
        else if (!(this.isBufferOrUint8Array(xorKey) || typeof xorKey == "number")) {
            throw new Error("XOR must be a number, string, Uint8Array or Buffer");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _XOR(bytes, 0, bytes.length, xorKey);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * XOR data.
     *
     * @param {number|string|Uint8Array|Buffer} xorKey - Value, string or array to XOR
     * @param {number} length - Length in bytes to XOR from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async xorThis(xorKey, length, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof xorKey == "number") {
            length = length ?? 1;
        }
        else if (typeof xorKey == "string") {
            xorKey = new TextEncoder().encode(xorKey);
            length = length ?? xorKey.length;
        }
        else if (this.isBufferOrUint8Array(xorKey)) {
            length = length ?? xorKey.length;
        }
        else {
            throw new Error("XOR must be a number, string, Uint8Array or Buffer");
        }
        return await this.xor(xorKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * OR data
     *
     * @param {number|string|Uint8Array|Buffer} orKey - Value, string or array to OR
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async or(orKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof orKey == "string") {
            orKey = new TextEncoder().encode(orKey);
        }
        else if (!(this.isBufferOrUint8Array(orKey) || typeof orKey == "number")) {
            throw new Error("OR must be a number, string, Uint8Array or Buffer");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _OR(bytes, 0, bytes.length, orKey);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * OR data.
     *
     * @param {number|string|Uint8Array|Buffer} orKey - Value, string or array to OR
     * @param {number} length - Length in bytes to OR from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async orThis(orKey, length, consume) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof orKey == "number") {
            length = length ?? 1;
        }
        else if (typeof orKey == "string") {
            orKey = new TextEncoder().encode(orKey);
            length = length ?? orKey.length;
        }
        else if (this.isBufferOrUint8Array(orKey)) {
            length = length ?? orKey.length;
        }
        else {
            throw new Error("OR must be a number, string, Uint8Array or Buffer");
        }
        return await this.or(orKey, this.#offset, this.#offset + length, consume || false);
    }
    ;
    /**
     * AND data.
     *
     * @param {number|string|Uint8Array|Buffer} andKey - Value, string or array to AND
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async and(andKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof andKey == "string") {
            andKey = new TextEncoder().encode(andKey);
        }
        else if (!(typeof andKey == "object" || typeof andKey == "number")) {
            throw new Error("AND must be a number, string, number array or Buffer");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _AND(bytes, 0, bytes.length, andKey);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * AND data.
     *
     * @param {number|string|Uint8Array|Buffer} andKey - Value, string or array to AND
     * @param {number} length - Length in bytes to AND from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async andThis(andKey, length, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof andKey == "number") {
            length = length ?? 1;
        }
        else if (typeof andKey == "string") {
            andKey = new TextEncoder().encode(andKey);
            length = length ?? andKey.length;
        }
        else if (this.isBufferOrUint8Array(andKey)) {
            length = length ?? andKey.length;
        }
        else {
            throw new Error("AND must be a number, string, Uint8Array or Buffer");
        }
        return await this.and(andKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Add value to data.
     *
     * @param {number|string|Uint8Array|Buffer} addKey - Value, string or array to add to data
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async add(addKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof addKey == "string") {
            addKey = new TextEncoder().encode(addKey);
        }
        else if (!(typeof addKey == "object" || typeof addKey == "number")) {
            throw new Error("Add key must be a number, string, number array or Buffer");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _ADD(bytes, 0, bytes.length, addKey);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * Add value to data.
     *
     * @param {number|string|Uint8Array|Buffer} addKey - Value, string or array to add to data
     * @param {number} length - Length in bytes to add from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async addThis(addKey, length, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof addKey == "number") {
            length = length ?? 1;
        }
        else if (typeof addKey == "string") {
            addKey = new TextEncoder().encode(addKey);
            length = length ?? addKey.length;
        }
        else if (this.isBufferOrUint8Array(addKey)) {
            length = length ?? addKey.length;
        }
        else {
            throw new Error("ADD must be a number, string, Uint8Array or Buffer");
        }
        return await this.add(addKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Not data.
     *
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async not(startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _NOT(bytes, 0, bytes.length);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * Not data.
     *
     * @param {number} length - Length in bytes to NOT from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async notThis(length = 1, consume = false) {
        return await this.not(this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Left shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to left shift data
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async lShift(shiftKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
        }
        else if (!(typeof shiftKey == "object" || typeof shiftKey == "number")) {
            throw new Error("Left shift must be a number, string, number array or Buffer");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _LSHIFT(bytes, 0, bytes.length, shiftKey);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * Left shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to left shift data
     * @param {number} length - Length in bytes to left shift from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async lShiftThis(shiftKey, length, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof shiftKey == "number") {
            length = length ?? 1;
        }
        else if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
            length = length ?? shiftKey.length;
        }
        else if (this.isBufferOrUint8Array(shiftKey)) {
            length = length ?? shiftKey.length;
        }
        else {
            throw new Error("Left shift must be a number, string, Uint8Array or Buffer");
        }
        return await this.lShift(shiftKey, this.#offset, this.#offset + length, consume);
    }
    ;
    /**
     * Right shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to right shift data
     * @param {number} startOffset - Start location (default current byte position)
     * @param {number} endOffset - End location (default end of data)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async rShift(shiftKey, startOffset = this.#offset, endOffset = this.size, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
        }
        else if (!(typeof shiftKey == "object" || typeof shiftKey == "number")) {
            throw new Error("Right shift must be a number, string, number array or Buffer");
        }
        const bytes = await this.#readBytes(Math.min(endOffset - startOffset, this.size - startOffset), consume);
        _RSHIFT(bytes, 0, bytes.length, shiftKey);
        return await this.#writeBytesAt(startOffset, bytes);
    }
    ;
    /**
     * Right shift data.
     *
     * @param {number|string|Uint8Array|Buffer} shiftKey - Value, string or array to right shift data
     * @param {number} length - Length in bytes to right shift from curent position (default 1 byte for value, length of string or array for Uint8Array or Buffer)
     * @param {boolean} consume - Move current position to end of data (default false)
     */
    async rShiftThis(shiftKey, length, consume = false) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (typeof shiftKey == "number") {
            length = length ?? 1;
        }
        else if (typeof shiftKey == "string") {
            shiftKey = new TextEncoder().encode(shiftKey);
            length = length ?? shiftKey.length;
        }
        else if (this.isBufferOrUint8Array(shiftKey)) {
            length = length ?? shiftKey.length;
        }
        else {
            throw new Error("right shift must be a number, string, Uint8Array or Buffer");
        }
        return await this.rShift(shiftKey, this.#offset, this.#offset + length, consume);
    }
    ;
    ///////////////////////////////
    // #region BIT READER
    ///////////////////////////////
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readBit(bits, unsigned = false, endian = this.endian, consume = true) {
        await this.open();
        if (typeof bits != "number") {
            throw new TypeError("Enter number of bits to read");
        }
        if (bits == 0) {
            return 0;
        }
        if (bits <= 0 || bits > 32) {
            throw new Error('Bit length must be between 1 and 32. Got ' + bits);
        }
        const byteEnd = Math.ceil((((bits - 1) + this.#insetBit) / 8) + this.#offset);
        if (byteEnd > this.size) {
            throw new Error(`Not enough bytes in file (need ${byteEnd}, have ${this.size})`);
        }
        const bitStart = (this.#offset * 8) + this.#insetBit;
        const byteStart = Math.floor(((this.#offset * 8) + this.#insetBit) / 8);
        const temp = await this.#peekBytes(byteStart, byteEnd - byteStart);
        const value = _rbit(temp, bits, bitStart % 8, endian, unsigned);
        if (consume) {
            this.#offset += Math.floor((bits + this.#insetBit) / 8); //end byte
            this.#insetBit = (bits + this.#insetBit) % 8;
        }
        return value;
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     */
    async readUBitBE(bits) {
        return await this.readBit(bits, true, "big");
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     */
    async readUBitLE(bits) {
        return await this.readBit(bits, true, "little");
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     */
    async readBitBE(bits, unsigned) {
        return await this.readBit(bits, unsigned, "big");
    }
    ;
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     */
    async readBitLE(bits, unsigned) {
        return await this.readBit(bits, unsigned, "little");
    }
    ;
    /**
     *
     * Write bits, must have at least value and number of bits.
     *
     * ``Note``: When returning to a byte write, remaining bits are skipped.
     *
     * @param {number} value - value as int
     * @param {number} bits - number of bits to write
     * @param {boolean} unsigned - if value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeBit(value, bits, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            this.errorDump ? console.log("\x1b[31m[Error]\x1b[0m hexdump:\n" + this.hexdump({ returnString: true })) : "";
            throw new Error("Can't write data in readOnly mode!");
        }
        await this.open();
        if (bits <= 0) {
            return;
        }
        if (bits <= 0 || bits > 32) {
            throw new Error('Bit length must be between 1 and 32. Got ' + bits);
        }
        value = numberSafe(value, bits, unsigned);
        const endOffset = Math.ceil((((bits - 1) + this.#insetBit) / 8) + this.#offset);
        const temp = await this.#peekBytes(this.#offset, Math.ceil(endOffset - this.#offset));
        _wbit(temp, value, bits, this.#insetBit, endian, unsigned);
        await this.#writeBytesAt(this.#offset, temp);
        if (consume) {
            this.#offset += Math.floor((bits + this.#insetBit) / 8);
            this.#insetBit = (bits + this.#insetBit) % 8;
        }
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @returns number
     */
    async writeUBitBE(value, bits) {
        return await this.writeBit(value, bits, true, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @returns number
     */
    async writeUBitLE(value, bits) {
        return await this.writeBit(value, bits, true, "little");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @returns number
     */
    async writeBitBE(value, bits, unsigned) {
        return await this.writeBit(value, bits, unsigned, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @returns number
     */
    async writeBitLE(value, bits, unsigned) {
        return await this.writeBit(value, bits, unsigned, "little");
    }
    ;
    ///////////////////////////////
    // #region BYTE READER
    ///////////////////////////////
    /**
     * Read byte.
     *
     * @param {boolean} unsigned - if the value is unsigned or not
     * @param {boolean} consume - move offset after read
     */
    async readByte(unsigned = false, consume = true) {
        await this.open();
        const data = await this.#readBytes(1, consume);
        var value = data[0];
        if (unsigned) {
            return value & 0xFF;
        }
        else {
            return value > 127 ? value - 256 : value;
        }
    }
    /**
     * Read unsigned byte.
     *
     * @param {boolean} consume - move offset after read
     */
    async readUByte(consume = true) {
        return await this.readByte(true, consume);
    }
    ;
    /**
     * Read multiple bytes.
     *
     * @param {number} amount - amount of bytes to read
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {boolean} consume - move offset after read
     */
    async readBytes(amount, unsigned, consume = true) {
        const data = await this.subarray(this.offset, this.offset + amount, consume);
        const returnArray = [];
        for (let i = 0; i < data.length; i++) {
            var value = data[0];
            if (unsigned) {
                returnArray.push(value & 0xFF);
            }
            else {
                returnArray.push(value > 127 ? value - 256 : value);
            }
        }
        return returnArray;
    }
    ;
    /**
     * Read multiple unsigned bytes.
     *
     * @param {number} amount - amount of bytes to read
     * @param {boolean} consume - move offset after read
     */
    async readUBytes(amount, consume = true) {
        return await this.subarray(this.offset, this.offset + amount, consume);
    }
    ;
    /**
     * Write byte.
     *
     * @param {number} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {boolean} consume - move offset after write
     */
    async writeByte(value, unsigned, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        await this.open();
        const single = new Uint8Array([numberSafe(value, 8, unsigned)]);
        await this.#writeBytes(single, consume);
    }
    ;
    /**
     * Write multiple bytes.
     *
     * @param {Array<number> | Buffer | Uint8Array} values - array of values as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {boolean} consume - move offset after write
     */
    async writeBytes(values, unsigned, consume = true) {
        if (this.isBufferOrUint8Array(values)) {
            await this.#writeBytes(values, consume);
            return;
        }
        else {
            const data = new Uint8Array(values);
            await this.#writeBytes(data, consume);
            return;
        }
    }
    ;
    /**
     * Write multiple unsigned bytes.
     *
     * @param {Array<number> | Buffer | Uint8Array} values - array of values as int
     * @param {boolean} consume - move offset after write
     */
    async writeUBytes(values, consume = true) {
        return await this.writeBytes(values, true, consume);
    }
    ;
    /**
     * Write unsigned byte.
     *
     * @param {number} value - value as int
     * @param {boolean} consume - move offset after write
     */
    async writeUByte(value, consume = true) {
        return await this.writeByte(value, consume);
    }
    ;
    ///////////////////////////////
    // #region INT16 READER
    ///////////////////////////////
    /**
     * Read short.
     *
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readInt16(unsigned = false, endian = this.endian, consume = true) {
        await this.open();
        const buf = await this.#readBytes(2, consume);
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        if (canInt16) {
            if (unsigned) {
                return view.getUint16(0, endian == "little");
            }
            else {
                return view.getInt16(0, endian == "little");
            }
        }
        else {
            return _rint16(buf, 0, endian, unsigned);
        }
    }
    ;
    /**
     * Read unsigned short.
     *
     * @param {endian} endian - ``big`` or ``little``
     */
    async readUInt16(endian = this.endian) {
        return await this.readInt16(true, endian);
    }
    ;
    /**
     * Read unsigned short in little endian.
     */
    async readUInt16LE() {
        return await this.readUInt16("little");
    }
    ;
    /**
     * Read unsigned short in big endian.
     */
    async readUInt16BE() {
        return await this.readUInt16("big");
    }
    ;
    /**
     * Read signed short in little endian.
     */
    async readInt16LE() {
        return await this.readInt16(false, "little");
    }
    ;
    /**
    * Read signed short in big endian.
    */
    async readInt16BE() {
        return await this.readInt16(false, "big");
    }
    ;
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeInt16(value, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (canInt16) {
            if (unsigned) {
                view2ByteDummy.setUint16(0, value, endian == "little");
            }
            else {
                view2ByteDummy.setInt16(0, value, endian == "little");
            }
        }
        else {
            _wint16(buff2ByteDummy, numberSafe(value, 16, unsigned), 0, endian, unsigned);
        }
        return await this.#writeBytes(buff2ByteDummy, consume);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeUInt16(value, endian = this.endian) {
        return await this.writeInt16(value, true, endian);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async writeUInt16BE(value) {
        return await this.writeUInt16(value, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async writeUInt16LE(value) {
        return await this.writeUInt16(value, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async writeInt16LE(value) {
        return await this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async writeInt16BE(value) {
        return await this.writeInt16(value, false, "big");
    }
    ;
    ///////////////////////////////
    // #region HALF FLOAT
    ///////////////////////////////
    /**
     * Read 16 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readHalfFloat(endian = this.endian, consume = true) {
        const buf = await this.#readBytes(2, consume);
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        if (canFloat16) {
            return view.getFloat16(0, endian == "little");
        }
        else {
            return _rhalffloat(buf, 0, endian);
        }
    }
    ;
    /**
     * Read 16 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readFloat16(endian = this.endian, consume = true) {
        return await this.readHalfFloat(endian, consume);
    }
    ;
    /**
    * Read 16 bit float.
    */
    async readHalfFloatBE() {
        return await this.readHalfFloat("big");
    }
    ;
    /**
    * Read 16 bit float.
    */
    async readFloat16BE() {
        return await this.readHalfFloat("big");
    }
    ;
    /**
     * Read 16 bit float.
     */
    async readHalfFloatLE() {
        return await this.readHalfFloat("little");
    }
    ;
    /**
     * Read 16 bit float.
     */
    async readFloat16LE() {
        return await this.readHalfFloat("little");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeHalfFloat(value, endian = this.endian, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (canFloat16) {
            view2ByteDummy.setFloat16(0, value, endian == "little");
        }
        else {
            _whalffloat(buff2ByteDummy, value, 0, endian);
        }
        return await this.#writeBytes(buff2ByteDummy, consume);
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeFloat16(value, endian = this.endian, consume = true) {
        return await this.writeHalfFloat(value, endian, consume);
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    async writeHalfFloatBE(value) {
        return await this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloat16BE(value) {
        return await this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    async writeHalfFloatLE(value) {
        return await this.writeHalfFloat(value, "little");
    }
    ;
    /**
     * Writes 16 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloat16LE(value) {
        return await this.writeHalfFloat(value, "little");
    }
    ;
    ///////////////////////////////
    // #region INT32 READER
    ///////////////////////////////
    /**
     * Read signed 32 bit integer.
     */
    async readInt32(unsigned = false, endian = this.endian, consume = true) {
        const buf = await this.#readBytes(4, consume);
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        if (canInt32) {
            if (unsigned) {
                return view.getUint32(0, endian == "little");
            }
            else {
                return view.getInt32(0, endian == "little");
            }
        }
        else {
            return _rint32(buf, 0, endian, unsigned);
        }
    }
    ;
    /**
     * Read signed 32 bit integer.
     */
    async readInt(endian) {
        return await this.readInt32(false, endian);
    }
    /**
     * Read signed 32 bit integer.
     */
    async readInt32BE() {
        return await this.readInt("big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     */
    async readInt32LE() {
        return await this.readInt("little");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @param {endian} endian - ``big`` or ``little``
     */
    async readUInt32(endian) {
        return await this.readInt32(true, endian);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @param {endian} endian - ``big`` or ``little``
     */
    async readUInt(endian) {
        return await this.readInt32(true, endian);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     */
    async readUInt32BE() {
        return await this.readUInt("big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     */
    async readUInt32LE() {
        return await this.readUInt("little");
    }
    ;
    /**
     * Write 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeInt32(value, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (canInt32) {
            if (unsigned) {
                view4ByteDummy.setUint32(0, value, endian == "little");
            }
            else {
                view4ByteDummy.setInt32(0, value, endian == "little");
            }
        }
        else {
            _wint32(buff4ByteDummy, numberSafe(value, 32, unsigned), 0, endian, unsigned);
        }
        return await this.#writeBytes(buff4ByteDummy, consume);
    }
    /**
     * Write signed 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeInt(value, endian) {
        return await this.writeInt32(value, false, endian);
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async writeInt32LE(value) {
        return await this.writeInt(value, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async writeInt32BE(value) {
        return await this.writeInt(value, "big");
    }
    ;
    /**
     * Write unsigned 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeUInt(value, endian) {
        return await this.writeInt32(value, true, endian);
    }
    ;
    /**
     * Write unsigned 32 bit integer.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeUInt32(value, endian) {
        return await this.writeUInt(value, endian);
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async writeUInt32BE(value) {
        return await this.writeUInt32(value, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async writeUInt32LE(value) {
        return await this.writeUInt32(value, "little");
    }
    ;
    ///////////////////////////////
    // #region FLOAT32 READER
    ///////////////////////////////
    /**
     * Read 32 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readFloat(endian = this.endian, consume = true) {
        const buf = await this.#readBytes(4, consume);
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        if (canFloat32) {
            return view.getFloat32(0, endian == "little");
        }
        else {
            return _rfloat(buf, 0, endian);
        }
    }
    ;
    /**
     * Read 32 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readFloat32(endian = this.endian, consume = true) {
        return await this.readFloat(endian, consume);
    }
    ;
    /**
     * Read 32 bit float.
     */
    async readFloatBE() {
        return await this.readFloat("big");
    }
    ;
    /**
     * Read 32 bit float.
     */
    async readFloat32BE() {
        return await this.readFloat("big");
    }
    ;
    /**
     * Read 32 bit float.
     */
    async readFloatLE() {
        return await this.readFloat("little");
    }
    ;
    /**
     * Read 32 bit float.
     */
    async readFloat32LE() {
        return await this.readFloat("little");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeFloat(value, endian = this.endian, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (canFloat32) {
            view4ByteDummy.setFloat32(0, value, endian == "little");
        }
        else {
            _wfloat(buff4ByteDummy, value, 0, endian);
        }
        return await this.#writeBytes(buff4ByteDummy, consume);
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloatLE(value) {
        return await this.writeFloat(value, "little");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloat32LE(value) {
        return await this.writeFloat(value, "little");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloat32BE(value) {
        return await this.writeFloat(value, "big");
    }
    ;
    /**
     * Write 32 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloatBE(value) {
        return await this.writeFloat(value, "big");
    }
    ;
    ///////////////////////////////
    // #region INT64 READER
    ///////////////////////////////
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     *
     * @param {boolean} unsigned - if value is unsigned or not
     * @param {endian?} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after read
     */
    async readInt64(unsigned = false, endian = this.endian, consume = true) {
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        const buf = await this.#readBytes(8, consume);
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        var value;
        if (canBigInt64) {
            if (unsigned) {
                value = view.getBigUint64(0, endian == "little");
            }
            else {
                value = view.getBigInt64(0, endian == "little");
            }
        }
        else {
            value = _rint64(buf, 0, endian, unsigned);
        }
        if (this.enforceBigInt == true || (typeof value == "bigint" && !isSafeInt64(value))) {
            return value;
        }
        else {
            if (isSafeInt64(value)) {
                return Number(value);
            }
            else {
                throw new Error("Value is outside of number range and enforceBigInt is set to false. " + value);
            }
        }
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async readUInt64() {
        return await this.readInt64(true);
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async readInt64BE() {
        return await this.readInt64(false, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async readInt64LE() {
        return await this.readInt64(false, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async readUInt64BE() {
        return await this.readInt64(true, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async readUInt64LE() {
        return await this.readInt64(true, "little");
    }
    ;
    /**
     * Write 64 bit integer.
     *
     * @param {BigValue} value - value as int
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @param {boolean} consume - move offset after write
     */
    async writeInt64(value, unsigned = false, endian = this.endian, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (!hasBigInt) {
            throw new Error("System doesn't support BigInt values.");
        }
        if (canBigInt64) {
            if (unsigned) {
                view8ByteDummy.setBigUint64(0, BigInt(value), endian == "little");
            }
            else {
                view8ByteDummy.setBigInt64(0, BigInt(value), endian == "little");
            }
        }
        else {
            _wint64(buff8ByteDummy, numberSafe(value, 64, unsigned), 0, endian, unsigned);
        }
        return await this.#writeBytes(buff8ByteDummy, consume);
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeUInt64(value, endian = this.endian) {
        return await this.writeInt64(value, true, endian);
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async writeInt64LE(value) {
        return await this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async writeInt64BE(value) {
        return await this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async writeUInt64LE(value) {
        return await this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async writeUInt64BE(value) {
        return await this.writeInt64(value, true, "big");
    }
    ;
    ///////////////////////////////
    // #region FLOAT64 READER
    ///////////////////////////////
    /**
     * Read 64 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     */
    async readDoubleFloat(endian = this.endian, consume = true) {
        const buf = await this.#readBytes(8, consume);
        const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
        if (canFloat64) {
            return view.getFloat64(0, endian == "little");
        }
        else {
            if (!hasBigInt) {
                throw new Error("System doesn't support BigInt values.");
            }
            return _rdfloat(buf, 0, endian);
        }
    }
    ;
    /**
     * Read 64 bit float.
     *
     * @param {endian} endian - ``big`` or ``little``
     */
    async readFloat64(endian = this.endian) {
        return await this.readDoubleFloat(endian);
    }
    ;
    /**
     * Read 64 bit float.
     */
    async readDoubleFloatBE() {
        return await this.readDoubleFloat("big");
    }
    ;
    /**
     * Read 64 bit float.
     */
    async readFloat64BE() {
        return await this.readDoubleFloat("big");
    }
    ;
    /**
     * Read 64 bit float.
     */
    async readDoubleFloatLE() {
        return await this.readDoubleFloat("little");
    }
    ;
    /**
     * Read 64 bit float.
     */
    async readFloat64LE() {
        return await this.readDoubleFloat("little");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeDoubleFloat(value, endian = this.endian, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        if (canFloat64) {
            view8ByteDummy.setFloat64(0, value, endian == "little");
        }
        else {
            _wdfloat(buff8ByteDummy, value, 0, endian);
        }
        return await this.#writeBytes(buff8ByteDummy, consume);
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     * @param {endian} endian - ``big`` or ``little``
     */
    async writeFloat64(value, endian = this.endian) {
        return await this.writeDoubleFloat(value, endian);
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    async writeDoubleFloatBE(value) {
        return await this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloat64BE(value) {
        return await this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    async writeDoubleFloatLE(value) {
        return await this.writeDoubleFloat(value, "little");
    }
    ;
    /**
     * Writes 64 bit float.
     *
     * @param {number} value - value as int
     */
    async writeFloat64LE(value) {
        return await this.writeDoubleFloat(value, "little");
    }
    ;
    ///////////////////////////////
    // #region STRING READER
    ///////////////////////////////
    /**
    * Reads string, use options object for different types.
    *
    * @param {stringOptions} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthReadSize"]?} options.lengthReadSize - for pascal strings. 1, 2 or 4 byte length read size
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for wide-pascal, double-wide-pascal and utf-16, utf-32
    * @param {boolean} consume - move offset after read
    */
    async readString(options = this.strDefaults, consume = true) {
        await this.open();
        var length = options.length;
        var stringType = options.stringType ?? 'utf-8';
        var terminateValue = options.terminateValue;
        var lengthReadSize = options.lengthReadSize ?? 1;
        var stripNull = options.stripNull ?? true;
        var endian = options.endian ?? this.endian;
        var encoding = options.encoding ?? 'utf-8';
        var terminate = terminateValue;
        var readLengthinBytes = 0;
        if (length != undefined) {
            switch (stringType) {
                case "utf-8":
                    readLengthinBytes = length;
                    break;
                case "utf-16":
                    readLengthinBytes = length * 2;
                    break;
                case "utf-32":
                    readLengthinBytes = length * 4;
                    break;
                default:
                    readLengthinBytes = length;
                    break;
            }
        }
        else {
            readLengthinBytes = this.data.length - this.#offset;
        }
        if (this.#offset + readLengthinBytes > this.size) {
            if (this.strict || this.readOnly) {
                throw new Error('Growing requires strict: false');
            }
            await this.#confrimSize(this.#offset + readLengthinBytes);
        }
        if (terminateValue != undefined && typeof terminateValue == "number") {
            terminate = terminateValue & 0xFF;
        }
        else {
            terminate = 0;
        }
        const saved_offset = this.#offset;
        const saved_bitoffset = this.#insetBit;
        const str = await _rstringAsync(stringType, lengthReadSize, readLengthinBytes, terminate, stripNull, encoding, endian, this.readUByte.bind(this), this.readUInt16.bind(this), this.readUInt32.bind(this));
        if (!consume) {
            this.#offset = saved_offset;
            this.#insetBit = saved_bitoffset;
        }
        return str;
    }
    ;
    /**
    * Writes string, use options object for different types.
    *
    * @param {string} string - text string
    * @param {stringOptions?} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthWriteSize"]?} options.lengthWriteSize - for pascal strings. 1, 2 or 4 byte length write size
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for wide-pascal, double-wide-pascal and utf-16, utf-32
    * @param {boolean} consume - move offset after write
    */
    async writeString(string, options = this.strDefaults, consume = true) {
        if (this.readOnly) {
            throw new Error("Can't write data in readOnly mode!");
        }
        await this.open();
        var length = options.length;
        var stringType = options.stringType ?? 'utf-8';
        var terminateValue = options.terminateValue;
        var lengthWriteSize = options.lengthWriteSize ?? 1;
        var endian = options.endian ?? this.endian;
        var maxLengthValue = length ?? string.length;
        var strUnits = string.length;
        var maxBytes;
        switch (stringType) {
            case 'pascal':
                maxLengthValue = 255;
                if (length != undefined) {
                    maxLengthValue = length;
                }
                break;
            case 'wide-pascal':
                strUnits *= 2;
                maxLengthValue = 65535;
                if (length != undefined) {
                    maxLengthValue = length / 2;
                }
                break;
            case 'double-wide-pascal':
                strUnits *= 4;
                maxLengthValue = 4294967295;
                if (length != undefined) {
                    maxLengthValue = length / 4;
                }
                break;
        }
        if (terminateValue == undefined) {
            if (stringType == "ascii" || stringType == 'utf-8' ||
                stringType == 'utf-16' ||
                stringType == 'utf-32') {
                terminateValue = 0;
            }
            if (length != undefined) {
                terminateValue = undefined;
            }
        }
        var maxBytes = Math.min(strUnits, maxLengthValue);
        string = string.substring(0, maxBytes);
        var encodedString;
        var totalLength = string.length;
        switch (stringType) {
            case 'ascii':
            case 'utf-8':
            case 'pascal':
                {
                    encodedString = new TextEncoder().encode(string);
                    totalLength = encodedString.byteLength + 1;
                    if (stringType == 'utf-8' && length) {
                        totalLength = length;
                    }
                }
                break;
            case 'utf-16':
            case 'wide-pascal':
                {
                    const utf16Buffer = new Uint16Array(string.length);
                    for (let i = 0; i < string.length; i++) {
                        utf16Buffer[i] = string.charCodeAt(i);
                    }
                    encodedString = new Uint8Array(utf16Buffer.buffer);
                    totalLength = encodedString.byteLength + 2;
                    if (stringType == 'utf-16' && length) {
                        totalLength = length;
                    }
                }
                break;
            case 'utf-32':
            case 'double-wide-pascal':
                {
                    const utf32Buffer = new Uint32Array(string.length);
                    for (let i = 0; i < string.length; i++) {
                        utf32Buffer[i] = string.codePointAt(i);
                    }
                    encodedString = new Uint8Array(utf32Buffer.buffer);
                    totalLength = encodedString.byteLength + 4;
                    if (stringType == 'utf-32' && length) {
                        totalLength = length;
                    }
                }
                break;
        }
        await this.#confrimSize(this.#offset + totalLength);
        const savedOffset = this.#offset;
        const savedBitOffset = this.#insetBit;
        await _wstringAsync(encodedString, stringType, endian, terminateValue, lengthWriteSize, this.writeUByte.bind(this), this.writeUInt16.bind(this), this.writeUInt32.bind(this));
        if (!consume) {
            this.#offset = savedOffset;
            this.#insetBit = savedBitOffset;
        }
    }
    ;
}
_a = BiBaseAsync;

/**
 * Async Binary reader, includes bitfields and strings.
 *
 * @param {DataType} input - File path or a `Buffer` or `Uint8Array`.
 * @param {BiOptions?} options - Any options to set at start
 * @param {BiOptions["byteOffset"]?} [options.byteOffset = 0] - Byte offset to start reader (default `0`)
 * @param {BiOptions["bitOffset"]?} [options.bitOffset = 0] - Bit offset (overrides {@link byteOffset}) (default `0`)
 * @param {BiOptions["endianness"]?} [options.endianness = "little"] - Endianness `big` or `little` (default `little`)
 * @param {BiOptions["strict"]?} [options.strict = true] - Strict mode: if `true` does not extend supplied array on outside read or write (default `true`)
 * @param {BiOptions["growthIncrement"]?} [options.growthIncrement = 1048576] - Amount of data to add when extending the buffer array when strict mode is false (default `1 MiB`)
 * @param {BiOptions["enforceBigInt"]?} [options.enforceBigInt = false] - 64 bit value reads will always return `bigint`. (default `false`)
 * @param {BiOptions["readOnly"]?} [options.readOnly = true] - Allow data writes when reading a file (default `true` in reader)
 * @param {BiOptions["windowSize"]?} [options.windowSize = 4096] - Size of the chunk of a file to load per read. Set to `0` to load the whole file in one async read (default `4 KiB`)
 *
 * @since 4.0
 */
class BiReaderAsync extends BiBaseAsync {
    constructor(input, options = {}) {
        options.byteOffset = options.byteOffset ?? 0;
        options.bitOffset = options.bitOffset ?? 0;
        options.endianness = options.endianness ?? "little";
        options.strict = options.strict ?? true;
        options.growthIncrement = options.growthIncrement ?? 0x100000;
        options.enforceBigInt = options.enforceBigInt ?? false;
        options.readOnly = options.readOnly ?? true;
        options.windowSize = options.windowSize ?? 0x1000;
        if (input == undefined) {
            throw new Error("Can not start BiReader without data.");
        }
        super(input, options);
    }
    ;
    /**
     * Creates and opens a new `BiReaderAsync`.
     *
     * @param {DataType} input - File path or a `Buffer` or `Uint8Array`.
     * @param {BiOptions?} options - Any options to set at start
     * @param {BiOptions["byteOffset"]?} [options.byteOffset = 0] - Byte offset to start reader (default `0`)
     * @param {BiOptions["bitOffset"]?} [options.bitOffset = 0] - Bit offset (overrides {@link byteOffset}) (default `0`)
     * @param {BiOptions["endianness"]?} [options.endianness = "little"] - Endianness `big` or `little` (default `little`)
     * @param {BiOptions["strict"]?} [options.strict = true] - Strict mode: if `true` does not extend supplied array on outside read or write (default `true`)
     * @param {BiOptions["growthIncrement"]?} [options.growthIncrement = 1048576] - Amount of data to add when extending the buffer array when strict mode is false (default `1 MiB`)
     * @param {BiOptions["enforceBigInt"]?} [options.enforceBigInt = false] - 64 bit value reads will always return `bigint`. (default `false`)
     * @param {BiOptions["readOnly"]?} [options.readOnly = true] - Allow data writes when reading a file (default `true` in reader)
     * @param {BiOptions["windowSize"]?} [options.windowSize = 4096] - Size of the chunk of a file to load per read. Set to `0` to load the whole file in one async read (default `4 KiB`)
     *
     * @since 4.0
     */
    static async create(input, options = {}) {
        const instance = new BiReaderAsync(input, options);
        await instance.open();
        return instance;
    }
    ;
    //
    // #region Bit Aliases
    //
    /**
     * Bit field reader.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     * @returns {Promise<number>}
     */
    async bit(bits, unsigned, endian) {
        return await this.readBit(bits, unsigned, endian);
    }
    ;
    /**
     * Bit field reader. Unsigned read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {endian} endian - ``big`` or ``little``
     * @returns {Promise<number>}
     */
    async ubit(bits, endian) {
        return await this.readBit(bits, true, endian);
    }
    ;
    /**
     * Bit field reader. Unsigned big endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @returns {Promise<number>}
     */
    async ubitbe(bits) {
        return await this.bit(bits, true, "big");
    }
    ;
    /**
     * Bit field reader. Big endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {Promise<number>}
     */
    async bitbe(bits, unsigned) {
        return await this.bit(bits, unsigned, "big");
    }
    ;
    /**
     * Bit field reader. Unsigned little endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @returns {Promise<number>}
     */
    async ubitle(bits) {
        return await this.bit(bits, true, "little");
    }
    ;
    /**
     * Bit field reader. Little endian read.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @param {number} bits - bits to read
     * @param {boolean} unsigned - if the value is unsigned
     * @returns {Promise<number>}
     */
    async bitle(bits, unsigned) {
        return await this.bit(bits, unsigned, "little");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit1() {
        return await this.bit(1);
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit1le() {
        return await this.bit(1, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit1be() {
        return await this.bit(1, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit1() {
        return await this.bit(1, true);
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit1le() {
        return await this.bit(1, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 1 bit.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit1be() {
        return await this.bit(1, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit2() {
        return await this.bit(2);
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit2le() {
        return await this.bit(2, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit2be() {
        return await this.bit(2, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit2() {
        return await this.bit(2, true);
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit2le() {
        return await this.bit(2, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 2 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit2be() {
        return await this.bit(2, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit3() {
        return await this.bit(3);
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit3le() {
        return await this.bit(3, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit3be() {
        return await this.bit(3, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit3() {
        return await this.bit(3, true);
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit3le() {
        return await this.bit(3, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 3 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit3be() {
        return await this.bit(3, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit4() {
        return await this.bit(4);
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit4le() {
        return await this.bit(4, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit4be() {
        return await this.bit(4, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit4() {
        return await this.bit(4, true);
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit4le() {
        return await this.bit(4, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 4 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit4be() {
        return await this.bit(4, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit5() {
        return await this.bit(5);
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit5le() {
        return await this.bit(5, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit5be() {
        return await this.bit(5, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit5() {
        return await this.bit(5, true);
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit5le() {
        return await this.bit(5, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 5 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit5be() {
        return await this.bit(5, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit6() {
        return await this.bit(6);
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit6le() {
        return await this.bit(6, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit6be() {
        return await this.bit(6, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit6() {
        return await this.bit(6, true);
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit6le() {
        return await this.bit(6, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 6 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit6be() {
        return await this.bit(6, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit7() {
        return await this.bit(7);
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit7le() {
        return await this.bit(7, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit7be() {
        return await this.bit(7, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit7() {
        return await this.bit(7, true);
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit7le() {
        return await this.bit(7, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 7 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit7be() {
        return await this.bit(7, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit8() {
        return await this.bit(8);
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit8le() {
        return await this.bit(8, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit8be() {
        return await this.bit(8, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit8() {
        return await this.bit(8, true);
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit8le() {
        return await this.bit(8, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 8 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit8be() {
        return await this.bit(8, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit9() {
        return await this.bit(9);
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit9le() {
        return await this.bit(9, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit9be() {
        return await this.bit(9, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit9() {
        return await this.bit(9, true);
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit9le() {
        return await this.bit(9, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 9 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit9be() {
        return await this.bit(9, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit10() {
        return await this.bit(10);
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit10le() {
        return await this.bit(10, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit10be() {
        return await this.bit(10, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit10() {
        return await this.bit(10, true);
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit10le() {
        return await this.bit(10, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 10 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit10be() {
        return await this.bit(10, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit11() {
        return await this.bit(11);
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit11le() {
        return await this.bit(11, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit11be() {
        return await this.bit(11, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit11() {
        return await this.bit(11, true);
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit11le() {
        return await this.bit(11, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 11 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit11be() {
        return await this.bit(11, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit12() {
        return await this.bit(12);
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit12le() {
        return await this.bit(12, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit12be() {
        return await this.bit(12, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit12() {
        return await this.bit(12, true);
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit12le() {
        return await this.bit(12, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 12 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit12be() {
        return await this.bit(12, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit13() {
        return await this.bit(13);
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit13le() {
        return await this.bit(13, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit13be() {
        return await this.bit(13, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit13() {
        return await this.bit(13, true);
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit13le() {
        return await this.bit(13, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 13 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit13be() {
        return await this.bit(13, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit14() {
        return await this.bit(14);
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit14le() {
        return await this.bit(14, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit14be() {
        return await this.bit(14, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit14() {
        return await this.bit(14, true);
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit14le() {
        return await this.bit(14, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 14 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit14be() {
        return await this.bit(14, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit15() {
        return await this.bit(15);
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {promise<number>}
     */
    async bit15le() {
        return await this.bit(15, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {promise<number>}
     */
    async bit15be() {
        return await this.bit(15, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit15() {
        return await this.bit(15, true);
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit15le() {
        return await this.bit(15, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 15 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit15be() {
        return await this.bit(15, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit16() {
        return await this.bit(16);
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit16le() {
        return await this.bit(16, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit16be() {
        return await this.bit(16, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit16() {
        return await this.bit(16, true);
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit16le() {
        return await this.bit(16, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 16 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit16be() {
        return await this.bit(16, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit17() {
        return await this.bit(17);
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit17le() {
        return await this.bit(17, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit17be() {
        return await this.bit(17, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit17() {
        return await this.bit(17, true);
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit17le() {
        return await this.bit(17, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 17 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit17be() {
        return await this.bit(17, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit18() {
        return await this.bit(18);
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit18le() {
        return await this.bit(18, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit18be() {
        return await this.bit(18, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit18() {
        return await this.bit(18, true);
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit18le() {
        return await this.bit(18, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 18 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit18be() {
        return await this.bit(18, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit19() {
        return await this.bit(19);
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit19le() {
        return await this.bit(19, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit19be() {
        return await this.bit(19, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit19() {
        return await this.bit(19, true);
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit19le() {
        return await this.bit(19, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 19 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit19be() {
        return await this.bit(19, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit20() {
        return await this.bit(20);
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit20le() {
        return await this.bit(20, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit20be() {
        return await this.bit(20, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit20() {
        return await this.bit(20, true);
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit20le() {
        return await this.bit(20, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 20 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit20be() {
        return await this.bit(20, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit21() {
        return await this.bit(21);
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit21le() {
        return await this.bit(21, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit21be() {
        return await this.bit(21, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit21() {
        return await this.bit(21, true);
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit21le() {
        return await this.bit(21, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 21 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit21be() {
        return await this.bit(21, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit22() {
        return await this.bit(22);
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit22le() {
        return await this.bit(22, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit22be() {
        return await this.bit(22, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit22() {
        return await this.bit(22, true);
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit22le() {
        return await this.bit(22, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 22 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit22be() {
        return await this.bit(22, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit23() {
        return await this.bit(23);
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit23le() {
        return await this.bit(23, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit23be() {
        return await this.bit(23, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit23() {
        return await this.bit(23, true);
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit23le() {
        return await this.bit(23, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 23 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit23be() {
        return await this.bit(23, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit24() {
        return await this.bit(24);
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit24le() {
        return await this.bit(24, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit24be() {
        return await this.bit(24, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit24() {
        return await this.bit(24, true);
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit24le() {
        return await this.bit(24, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 24 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit24be() {
        return await this.bit(24, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit25() {
        return await this.bit(25);
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit25le() {
        return await this.bit(25, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit25be() {
        return await this.bit(25, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit25() {
        return await this.bit(25, true);
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit25le() {
        return await this.bit(25, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 25 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit25be() {
        return await this.bit(25, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit26() {
        return await this.bit(26);
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit26le() {
        return await this.bit(26, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit26be() {
        return await this.bit(26, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit26() {
        return await this.bit(26, true);
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit26le() {
        return await this.bit(26, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 26 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit26be() {
        return await this.bit(26, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit27() {
        return await this.bit(27);
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit27le() {
        return await this.bit(27, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit27be() {
        return await this.bit(27, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit27() {
        return await this.bit(27, true);
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit27le() {
        return await this.bit(27, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 27 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit27be() {
        return await this.bit(27, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit28() {
        return await this.bit(28);
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit28le() {
        return await this.bit(28, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit28be() {
        return await this.bit(28, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit28() {
        return await this.bit(28, true);
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit28le() {
        return await this.bit(28, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 28 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit28be() {
        return await this.bit(28, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit29() {
        return await this.bit(29);
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit29le() {
        return await this.bit(29, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit29be() {
        return await this.bit(29, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit29() {
        return await this.bit(29, true);
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit29le() {
        return await this.bit(29, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 29 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit29be() {
        return await this.bit(29, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit30() {
        return await this.bit(30);
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit30le() {
        return await this.bit(30, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit30be() {
        return await this.bit(30, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit30() {
        return await this.bit(30, true);
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit30le() {
        return await this.bit(30, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 30 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit30be() {
        return await this.bit(30, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit31() {
        return await this.bit(31);
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit31le() {
        return await this.bit(31, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit31be() {
        return await this.bit(31, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit31() {
        return await this.bit(31, true);
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit31le() {
        return await this.bit(31, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 31 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit31be() {
        return await this.bit(31, true, "big");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit32() {
        return await this.bit(32);
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit32le() {
        return await this.bit(32, undefined, "little");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async bit32be() {
        return await this.bit(32, undefined, "big");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit32() {
        return await this.bit(32, true);
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit32le() {
        return await this.bit(32, true, "little");
    }
    ;
    /**
     * Bit field reader. Reads 32 bits.
     *
     * Note: When returning to a byte read, remaining bits are dropped.
     *
     * @returns {Promise<number>}
     */
    async ubit32be() {
        return await this.bit(32, true, "big");
    }
    ;
    //
    // #region byte read
    //
    /**
     * Read byte.
     *
     * @returns {Promise<number>}
     */
    async byte() {
        return await this.readByte();
    }
    ;
    /**
     * Read byte.
     *
     * @returns {Promise<number>}
     */
    async int8() {
        return await this.readByte();
    }
    ;
    /**
     * Read unsigned byte.
     *
     * @returns {Promise<number>}
     */
    async uint8() {
        return await this.readByte(true);
    }
    ;
    /**
     * Read unsigned byte.
     *
     * @returns {Promise<number>}
     */
    async ubyte() {
        return await this.readByte(true);
    }
    ;
    //
    // #region short16 read
    //
    /**
     * Read short.
     *
     * @returns {Promise<number>}
     */
    async int16() {
        return await this.readInt16();
    }
    ;
    /**
     * Read short.
     *
     * @returns {Promise<number>}
     */
    async short() {
        return await this.readInt16();
    }
    ;
    /**
     * Read short.
     *
     * @returns {Promise<number>}
     */
    async word() {
        return await this.readInt16();
    }
    ;
    /**
     * Read unsigned short.
     *
     * @returns {Promise<number>}
     */
    async uint16() {
        return await this.readInt16(true);
    }
    ;
    /**
     * Read unsigned short.
     *
     * @returns {Promise<number>}
     */
    async ushort() {
        return this.readInt16(true);
    }
    ;
    /**
     * Read unsigned short.
     *
     * @returns {Promise<number>}
     */
    async uword() {
        return await this.readInt16(true);
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {Promise<number>}
     */
    async uint16le() {
        return await this.readInt16(true, "little");
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {Promise<number>}
     */
    async ushortle() {
        return await this.readInt16(true, "little");
    }
    ;
    /**
     * Read unsigned short in little endian.
     *
     * @returns {Promise<number>}
     */
    async uwordle() {
        return await this.readInt16(true, "little");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {Promise<number>}
     */
    async int16le() {
        return await this.readInt16(false, "little");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {Promise<number>}
     */
    async shortle() {
        return await this.readInt16(false, "little");
    }
    ;
    /**
     * Read signed short in little endian.
     *
     * @returns {Promise<number>}
     */
    async wordle() {
        return await this.readInt16(false, "little");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {Promise<number>}
     */
    async uint16be() {
        return await this.readInt16(true, "big");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {Promise<number>}
     */
    async ushortbe() {
        return await this.readInt16(true, "big");
    }
    ;
    /**
     * Read unsigned short in big endian.
     *
     * @returns {Promise<number>}
     */
    async uwordbe() {
        return await this.readInt16(true, "big");
    }
    ;
    /**
     * Read signed short in big endian.
     *
     * @returns {Promise<number>}
     */
    async int16be() {
        return await this.readInt16(false, "big");
    }
    ;
    /**
     * Read signed short in big endian.
     *
     * @returns {Promise<number>}
     */
    async shortbe() {
        return await this.readInt16(false, "big");
    }
    ;
    /**
     * Read signed short in big endian.
     *
     * @returns {Promise<number>}
     */
    async wordbe() {
        return await this.readInt16(false, "big");
    }
    ;
    //
    // #region half float read
    //
    /**
     * Read half float.
     *
     * @returns {Promise<number>}
     */
    async halffloat() {
        return await this.readHalfFloat();
    }
    ;
    /**
     * Read half float
     *
     * @returns {Promise<number>}
     */
    async half() {
        return await this.readHalfFloat();
    }
    ;
    /**
     * Read half float.
     *
     * @returns {Promise<number>}
     */
    async halffloatbe() {
        return await this.readHalfFloat("big");
    }
    ;
    /**
     * Read half float.
     *
     * @returns {Promise<number>}
     */
    async halfbe() {
        return await this.readHalfFloat("big");
    }
    ;
    /**
     * Read half float.
     *
     * @returns {Promise<number>}
     */
    async halffloatle() {
        return await this.readHalfFloat("little");
    }
    ;
    /**
     * Read half float.
     *
     * @returns {Promise<number>}
     */
    async halfle() {
        return await this.readHalfFloat("little");
    }
    ;
    //
    // #region int read
    //
    /**
     * Read 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async int() {
        return await this.readInt32();
    }
    ;
    /**
     * Read 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async double() {
        return await this.readInt32();
    }
    ;
    /**
     * Read 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async int32() {
        return await this.readInt32();
    }
    ;
    /**
     * Read 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async long() {
        return await this.readInt32();
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async uint() {
        return await this.readInt32(true);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async udouble() {
        return await this.readInt32(true);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async uint32() {
        return await this.readInt32(true);
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async ulong() {
        return await this.readInt32(true);
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async intbe() {
        return await this.readInt32(false, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async doublebe() {
        return await this.readInt32(false, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async int32be() {
        return await this.readInt32(false, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async longbe() {
        return await this.readInt32(false, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async uintbe() {
        return await this.readInt32(true, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async udoublebe() {
        return await this.readInt32(true, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async uint32be() {
        return await this.readInt32(true, "big");
    }
    ;
    /**
     * Read unsigned 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async ulongbe() {
        return await this.readInt32(true, "big");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async intle() {
        return await this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async doublele() {
        return await this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async int32le() {
        return await this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async longle() {
        return await this.readInt32(false, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async uintle() {
        return await this.readInt32(true, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async udoublele() {
        return await this.readInt32(true, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async uint32le() {
        return await this.readInt32(true, "little");
    }
    ;
    /**
     * Read signed 32 bit integer.
     *
     * @returns {Promise<number>}
     */
    async ulongle() {
        return await this.readInt32(true, "little");
    }
    ;
    //
    // #region float read
    //
    /**
     * Read float.
     *
     * @returns {Promise<number>}
     */
    async float() {
        return await this.readFloat();
    }
    ;
    /**
     * Read float.
     *
     * @returns {Promise<number>}
     */
    async floatbe() {
        return await this.readFloat("big");
    }
    ;
    /**
     * Read float.
     *
     * @returns {Promise<number>}
     */
    async floatle() {
        return await this.readFloat("little");
    }
    ;
    //
    // #region int64 reader
    //
    /**
     * Read signed 64 bit integer
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async int64() {
        return await this.readInt64();
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async bigint() {
        return await this.readInt64();
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async quad() {
        return await this.readInt64();
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async uint64() {
        return await this.readInt64(true);
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async ubigint() {
        return await this.readInt64(true);
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async uquad() {
        return await this.readInt64(true);
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async int64be() {
        return await this.readInt64(false, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async bigintbe() {
        return await this.readInt64(false, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async quadbe() {
        return await this.readInt64(false, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async uint64be() {
        return await this.readInt64(true, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async ubigintbe() {
        return await this.readInt64(true, "big");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async uquadbe() {
        return await this.readInt64(true, "big");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async int64le() {
        return await this.readInt64(false, "little");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async bigintle() {
        return await this.readInt64(false, "little");
    }
    ;
    /**
     * Read signed 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async quadle() {
        return await this.readInt64(false, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async uint64le() {
        return await this.readInt64(true, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async ubigintle() {
        return await this.readInt64(true, "little");
    }
    ;
    /**
     * Read unsigned 64 bit integer.
     *
     * Note: If ``enforceBigInt`` was set to ``true``, this always returns a ``BigInt`` otherwise it will return a ``number`` if integer safe.
     */
    async uquadle() {
        return await this.readInt64(true, "little");
    }
    ;
    //
    // #region doublefloat reader
    //
    /**
     * Read double float.
     *
     * @returns {Promise<number>}
     */
    async doublefloat() {
        return await this.readDoubleFloat();
    }
    ;
    /**
     * Read double float.
     *
     * @returns {Promise<number>}
     */
    async dfloat() {
        return await this.readDoubleFloat();
    }
    ;
    /**
     * Read double float.
     *
     * @returns {Promise<number>}
     */
    async dfloatbe() {
        return await this.readDoubleFloat("big");
    }
    ;
    /**
     * Read double float.
     *
     * @returns {Promise<number>}
     */
    async doublefloatbe() {
        return await this.readDoubleFloat("big");
    }
    ;
    /**
     * Read double float.
     *
     * @returns {Promise<number>}
     */
    async dfloatle() {
        return await this.readDoubleFloat("little");
    }
    ;
    /**
     * Read double float.
     *
     * @returns {Promise<number>}
     */
    async doublefloatle() {
        return await this.readDoubleFloat("little");
    }
    ;
    //
    // #region string reader
    //
    /**
    * Reads string, use options object for different types.
    *
    * @param {stringOptions} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - ascii, utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthReadSize"]?} options.lengthReadSize - for pascal strings. 1, 2 or 4 byte length read size
    * @param {stringOptions["stripNull"]?} options.stripNull - removes 0x00 characters
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for utf-16, utf-32, wide-pascal or double-wide-pascal
    * @returns {string}
    */
    async string(options) {
        return await this.readString(options);
    }
    ;
    /**
    * Reads string using setting from .strDefaults
    *
    * Default is ``utf-8``
    *
    * @returns {Promise<string>}
    */
    async str() {
        return await this.readString(this.strDefaults);
    }
    ;
    /**
    * Reads UTF-8 (C) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async utf8string(length, terminateValue, stripNull) {
        return await this.string({ stringType: "utf-8", encoding: "utf-8", length: length, terminateValue: terminateValue, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-8 (C) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async cstring(length, terminateValue, stripNull) {
        return await this.utf8string(length, terminateValue, stripNull);
    }
    ;
    /**
    * Reads ANSI string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async ansistring(length, terminateValue, stripNull) {
        return await this.string({ stringType: "utf-8", encoding: "windows-1252", length: length, terminateValue: terminateValue, stripNull: stripNull });
    }
    ;
    /**
    * Reads latin1 string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async latin1string(length, terminateValue, stripNull) {
        return await this.string({ stringType: "utf-8", encoding: "iso-8859-1", length: length, terminateValue: terminateValue, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async utf16string(length, terminateValue, stripNull, endian) {
        return await this.string({ stringType: "utf-16", encoding: "utf-16", length: length, terminateValue: terminateValue, endian: endian, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async unistring(length, terminateValue, stripNull, endian) {
        return await this.utf16string(length, terminateValue, stripNull, endian);
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in little endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async utf16stringle(length, terminateValue, stripNull) {
        return await this.utf16string(length, terminateValue, stripNull, "little");
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in little endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async unistringle(length, terminateValue, stripNull) {
        return await this.utf16stringle(length, terminateValue, stripNull);
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in big endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async utf16stringbe(length, terminateValue, stripNull) {
        return await this.utf16string(length, terminateValue, stripNull, "big");
    }
    ;
    /**
    * Reads UTF-16 (Unicode) string in big endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async unistringbe(length, terminateValue, stripNull) {
        return await this.utf16stringbe(length, terminateValue, stripNull);
    }
    ;
    /**
    * Reads UTF-32 (Unicode) string.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async utf32string(length, terminateValue, stripNull, endian) {
        return await this.string({ stringType: "utf-32", encoding: "utf-32", length: length, terminateValue: terminateValue, endian: endian, stripNull: stripNull });
    }
    ;
    /**
    * Reads UTF-32 (Unicode) string in little endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async utf32stringle(length, terminateValue, stripNull) {
        return await this.utf32string(length, terminateValue, stripNull, "little");
    }
    ;
    /**
    * Reads UTF-32 (Unicode) string in big endian order.
    *
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async utf32stringbe(length, terminateValue, stripNull) {
        return await this.utf32string(length, terminateValue, stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async pstring(lengthReadSize, stripNull, endian) {
        return await this.string({ stringType: "pascal", encoding: "utf-8", lengthReadSize: lengthReadSize, stripNull: stripNull, endian: endian });
    }
    ;
    /**
    * Reads Pascal string 1 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async pstring1(stripNull, endian) {
        return await this.pstring(1, stripNull, endian);
    }
    ;
    /**
    * Reads Pascal string 1 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async pstring1le(stripNull) {
        return await this.pstring1(stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string 1 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async pstring1be(stripNull) {
        return await this.pstring1(stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string 2 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async pstring2(stripNull, endian) {
        return await this.pstring(2, stripNull, endian);
    }
    ;
    /**
    * Reads Pascal string 2 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async pstring2le(stripNull) {
        return await this.pstring2(stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string 2 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async pstring2be(stripNull) {
        return await this.pstring2(stripNull, "big");
    }
    ;
    /**
    * Reads Pascal string 4 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async pstring4(stripNull, endian) {
        return await this.pstring(4, stripNull, endian);
    }
    ;
    /**
    * Reads Pascal string 4 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async pstring4le(stripNull) {
        return await this.pstring4(stripNull, "little");
    }
    ;
    /**
    * Reads Pascal string 4 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async pstring4be(stripNull) {
        return await this.pstring4(stripNull, "big");
    }
    ;
    /**
    * Reads Wide-Pascal string.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async wpstring(lengthReadSize, stripNull, endian) {
        return await this.string({ stringType: "wide-pascal", encoding: "utf-16", lengthReadSize: lengthReadSize, endian: endian, stripNull: stripNull });
    }
    ;
    /**
    * Reads Wide-Pascal string in little endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstringle(lengthReadSize, stripNull) {
        return await this.wpstring(lengthReadSize, stripNull, "little");
    }
    ;
    /**
    * Reads Wide-Pascal string in big endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstringbe(lengthReadSize, stripNull) {
        return await this.wpstring(lengthReadSize, stripNull, "big");
    }
    ;
    /**
    * Reads Wide-Pascal string 1 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async wpstring1(stripNull, endian) {
        return await this.wpstring(1, stripNull, endian);
    }
    ;
    /**
    * Reads Wide-Pascal string 1 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstring1le(stripNull) {
        return await this.wpstring1(stripNull, "little");
    }
    ;
    /**
    * Reads Wide-Pascal string 1 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstring1be(stripNull) {
        return await this.wpstring1(stripNull, "big");
    }
    ;
    /**
    * Reads Wide-Pascal string 2 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async wpstring2(stripNull, endian) {
        return await this.wpstring(2, stripNull, endian);
    }
    ;
    /**
    * Reads Wide-Pascal string 2 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstring2le(stripNull) {
        return await this.wpstring2(stripNull, "little");
    }
    ;
    /**
    * Reads Wide-Pascal string 2 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstring2be(stripNull) {
        return await this.wpstring2(stripNull, "big");
    }
    ;
    /**
    * Reads Wide-Pascal string 4 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async wpstring4(stripNull, endian) {
        return await this.wpstring(4, stripNull, endian);
    }
    ;
    /**
    * Reads Wide-Pascal string 4 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstring4le(stripNull) {
        return await this.wpstring4(stripNull, "little");
    }
    ;
    /**
    * Reads Wide-Pascal string 4 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async wpstring4be(stripNull) {
        return await this.wpstring4(stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async dwpstring(lengthReadSize, stripNull, endian) {
        return await this.string({ stringType: "double-wide-pascal", encoding: "utf-32", lengthReadSize: lengthReadSize, stripNull: stripNull, endian: endian });
    }
    ;
    /**
    * Reads Double Wide Pascal string in little endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstringle(lengthReadSize, stripNull) {
        return await this.dwpstring(lengthReadSize, stripNull, "little");
    }
    ;
    /**
    * Reads Double Wide Pascal string in big endian.
    *
    * @param {stringOptions["lengthReadSize"]} lengthReadSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstringbe(lengthReadSize, stripNull) {
        return await this.dwpstring(lengthReadSize, stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string 1 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async dwpstring1(stripNull, endian) {
        return await this.dwpstring(1, stripNull, endian);
    }
    ;
    /**
    * Reads Double Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstring1le(stripNull) {
        return await this.dwpstring1(stripNull, "little");
    }
    ;
    /**
    * Reads Double WidePascal string 1 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstring1be(stripNull) {
        return await this.dwpstring1(stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string 2 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async dwpstring2(stripNull, endian) {
        return await this.dwpstring(2, stripNull, endian);
    }
    ;
    /**
    * Reads Double Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstring2le(stripNull) {
        return await this.dwpstring2(stripNull, "little");
    }
    ;
    /**
    * Reads Double Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstring2be(stripNull) {
        return await this.dwpstring2(stripNull, "big");
    }
    ;
    /**
    * Reads Double Wide Pascal string 4 byte length read.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    *
    * @returns {Promise<string>}
    */
    async dwpstring4(stripNull, endian) {
        return await this.dwpstring(4, stripNull, endian);
    }
    ;
    /**
    * Reads Double Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstring4le(stripNull) {
        return await this.dwpstring4(stripNull, "little");
    }
    ;
    /**
    * Reads Double Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {stringOptions["stripNull"]} stripNull - removes 0x00 characters
    *
    * @returns {Promise<string>}
    */
    async dwpstring4be(stripNull) {
        return await this.dwpstring4(stripNull, "big");
    }
    ;
}

/**
 * Async Binary writer, includes bitfields and strings.
 *
 * @param {DataType} input - File path or a `Buffer` or ``Uint8Array`.
 * @param {BiOptions?} options - Any options to set at start
 * @param {BiOptions["byteOffset"]?} [options.byteOffset = 0] - Byte offset to start reader (default `0`)
 * @param {BiOptions["bitOffset"]?} [options.bitOffset = 0] - Bit offset (overrides {@link byteOffset}) (default `0`)
 * @param {BiOptions["endianness"]?} [options.endianness = "little"] - Endianness `big` or `little` (default `little`)
 * @param {BiOptions["strict"]?} [options.strict = true] - Strict mode: if `true` does not extend supplied array on outside read or write (default `true`)
 * @param {BiOptions["growthIncrement"]?} [options.growthIncrement = 1048576] - Amount of data to add when extending the buffer array when strict mode is false (default `1 MiB`)
 * @param {BiOptions["enforceBigInt"]?} [options.enforceBigInt = false] - 64 bit value reads will always return `bigint`. (default `false`)
 * @param {BiOptions["windowSize"]?} [options.windowSize = 4096] - Size of the chunk of a file to load per read. Set to `0` to load the whole file in one async read (default `4 KiB`)
 *
 * @since 4.0
 */
class BiWriterAsync extends BiBaseAsync {
    constructor(input, options = {}) {
        options.byteOffset = options.byteOffset ?? 0;
        options.bitOffset = options.bitOffset ?? 0;
        options.endianness = options.endianness ?? "little";
        options.strict = options.strict ?? false;
        options.growthIncrement = options.growthIncrement ?? 0x100000;
        options.enforceBigInt = options.enforceBigInt ?? false;
        options.readOnly = options.readOnly ?? false;
        options.windowSize = options.windowSize ?? 0x1000;
        const { growthIncrement, } = options;
        if (input == undefined) {
            input = new Uint8Array(growthIncrement);
            console.warn(`BiWriter started without data. Creating Uint8Array with growthIncrement.`);
        }
        super(input, options);
    }
    ;
    /**
     *
     * Creates and opens a new `BiWriterAsync`.
     *
     * @param {DataType} input - File path or a `Buffer` or ``Uint8Array`.
     * @param {BiOptions?} options - Any options to set at start
     * @param {BiOptions["byteOffset"]?} [options.byteOffset = 0] - Byte offset to start reader (default `0`)
     * @param {BiOptions["bitOffset"]?} [options.bitOffset = 0] - Bit offset (overrides {@link byteOffset}) (default `0`)
     * @param {BiOptions["endianness"]?} [options.endianness = "little"] - Endianness `big` or `little` (default `little`)
     * @param {BiOptions["strict"]?} [options.strict = true] - Strict mode: if `true` does not extend supplied array on outside read or write (default `true`)
     * @param {BiOptions["growthIncrement"]?} [options.growthIncrement = 1048576] - Amount of data to add when extending the buffer array when strict mode is false (default `1 MiB`)
     * @param {BiOptions["enforceBigInt"]?} [options.enforceBigInt = false] - 64 bit value reads will always return `bigint`. (default `false`)
     * @param {BiOptions["windowSize"]?} [options.windowSize = 4096] - Size of the chunk of a file to load per read. Set to `0` to load the whole file in one async read (default `4 KiB`)
     *
     * @returns {Promise<BiWriterAsync<DataType, alwaysBigInt>>}
     */
    static async create(input, options = {}) {
        const instance = new BiWriterAsync(input, options);
        await instance.open();
        return instance;
    }
    ;
    //
    // #region Bit Aliases
    //
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     * @param {endian} endian - ``big`` or ``little``
     */
    async bit(value, bits, unsigned, endian) {
        return await this.writeBit(value, bits, unsigned, endian);
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {endian} endian - ``big`` or ``little``
     */
    async ubit(value, bits, endian) {
        return await this.writeBit(value, bits, true, endian);
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     */
    async bitbe(value, bits, unsigned) {
        return await this.bit(value, bits, unsigned, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     */
    async ubitbe(value, bits) {
        return await this.bit(value, bits, true, "big");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     */
    async ubitle(value, bits) {
        return await this.bit(value, bits, true, "little");
    }
    ;
    /**
     * Bit field writer.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     * @param {number} bits - bits to write
     * @param {boolean} unsigned - if the value is unsigned
     */
    async bitle(value, bits, unsigned) {
        return await this.bit(value, bits, unsigned, "little");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit1(value) {
        await this.bit(value, 1);
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit1le(value) {
        await this.bit(value, 1, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit1be(value) {
        await this.bit(value, 1, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit1(value) {
        await this.bit(value, 1, true);
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit1le(value) {
        await this.bit(value, 1, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 1 bit.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit1be(value) {
        await this.bit(value, 1, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit2(value) {
        await this.bit(value, 2);
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit2le(value) {
        await this.bit(value, 2, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit2be(value) {
        await this.bit(value, 2, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit2(value) {
        await this.bit(value, 2, true);
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit2le(value) {
        await this.bit(value, 2, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 2 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit2be(value) {
        await this.bit(value, 2, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit3(value) {
        await this.bit(value, 3);
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit3le(value) {
        await this.bit(value, 3, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit3be(value) {
        await this.bit(value, 3, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit3(value) {
        await this.bit(value, 3, true);
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit3le(value) {
        await this.bit(value, 3, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 3 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit3be(value) {
        await this.bit(value, 3, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit4(value) {
        await this.bit(value, 4);
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit4le(value) {
        await this.bit(value, 4, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit4be(value) {
        await this.bit(value, 4, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit4(value) {
        await this.bit(value, 4, true);
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit4le(value) {
        await this.bit(value, 4, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 4 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit4be(value) {
        await this.bit(value, 4, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit5(value) {
        await this.bit(value, 5);
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit5le(value) {
        await this.bit(value, 5, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit5be(value) {
        await this.bit(value, 5, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit5(value) {
        await this.bit(value, 5, true);
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit5le(value) {
        await this.bit(value, 5, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 5 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit5be(value) {
        await this.bit(value, 5, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit6(value) {
        await this.bit(value, 6);
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit6le(value) {
        await this.bit(value, 6, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit6be(value) {
        await this.bit(value, 6, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit6(value) {
        await this.bit(value, 6, true);
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit6le(value) {
        await this.bit(value, 6, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 6 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit6be(value) {
        await this.bit(value, 6, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit7(value) {
        await this.bit(value, 7);
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit7le(value) {
        await this.bit(value, 7, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit7be(value) {
        await this.bit(value, 7, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit7(value) {
        await this.bit(value, 7, true);
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit7le(value) {
        await this.bit(value, 7, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 7 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit7be(value) {
        await this.bit(value, 7, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit8(value) {
        await this.bit(value, 8);
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit8le(value) {
        await this.bit(value, 8, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit8be(value) {
        await this.bit(value, 8, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit8(value) {
        await this.bit(value, 8, true);
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit8le(value) {
        await this.bit(value, 8, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 8 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit8be(value) {
        await this.bit(value, 8, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit9(value) {
        await this.bit(value, 9);
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit9le(value) {
        await this.bit(value, 9, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit9be(value) {
        await this.bit(value, 9, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit9(value) {
        await this.bit(value, 9, true);
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit9le(value) {
        await this.bit(value, 9, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 9 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit9be(value) {
        await this.bit(value, 9, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit10(value) {
        await this.bit(value, 10);
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit10le(value) {
        await this.bit(value, 10, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit10be(value) {
        await this.bit(value, 10, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit10(value) {
        await this.bit(value, 10, true);
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit10le(value) {
        await this.bit(value, 10, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 10 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit10be(value) {
        await this.bit(value, 10, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit11(value) {
        await this.bit(value, 11);
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit11le(value) {
        await this.bit(value, 11, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit11be(value) {
        await this.bit(value, 11, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit11(value) {
        await this.bit(value, 11, true);
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit11le(value) {
        await this.bit(value, 11, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 11 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit11be(value) {
        await this.bit(value, 11, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit12(value) {
        await this.bit(value, 12);
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit12le(value) {
        await this.bit(value, 12, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit12be(value) {
        await this.bit(value, 12, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit12(value) {
        await this.bit(value, 12, true);
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit12le(value) {
        await this.bit(value, 12, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 12 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit12be(value) {
        await this.bit(value, 12, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit13(value) {
        await this.bit(value, 13);
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit13le(value) {
        await this.bit(value, 13, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit13be(value) {
        await this.bit(value, 13, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit13(value) {
        await this.bit(value, 13, true);
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit13le(value) {
        await this.bit(value, 13, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 13 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit13be(value) {
        await this.bit(value, 13, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit14(value) {
        await this.bit(value, 14);
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit14le(value) {
        await this.bit(value, 14, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit14be(value) {
        await this.bit(value, 14, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit14(value) {
        await this.bit(value, 14, true);
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit14le(value) {
        await this.bit(value, 14, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 14 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit14be(value) {
        await this.bit(value, 14, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit15(value) {
        await this.bit(value, 15);
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit15le(value) {
        await this.bit(value, 15, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit15be(value) {
        await this.bit(value, 15, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit15(value) {
        await this.bit(value, 15, true);
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit15le(value) {
        await this.bit(value, 15, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 15 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit15be(value) {
        await this.bit(value, 15, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit16(value) {
        await this.bit(value, 16);
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit16le(value) {
        await this.bit(value, 16, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit16be(value) {
        await this.bit(value, 16, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit16(value) {
        await this.bit(value, 16, true);
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit16le(value) {
        await this.bit(value, 16, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 16 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit16be(value) {
        await this.bit(value, 16, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit17(value) {
        await this.bit(value, 17);
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit17le(value) {
        await this.bit(value, 17, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit17be(value) {
        await this.bit(value, 17, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit17(value) {
        await this.bit(value, 17, true);
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit17le(value) {
        await this.bit(value, 17, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 17 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit17be(value) {
        await this.bit(value, 17, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit18(value) {
        await this.bit(value, 18);
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit18le(value) {
        await this.bit(value, 18, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit18be(value) {
        await this.bit(value, 18, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit18(value) {
        await this.bit(value, 18, true);
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit18le(value) {
        await this.bit(value, 18, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 18 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit18be(value) {
        await this.bit(value, 18, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit19(value) {
        await this.bit(value, 19);
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit19le(value) {
        await this.bit(value, 19, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit19be(value) {
        await this.bit(value, 19, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit19(value) {
        await this.bit(value, 19, true);
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit19le(value) {
        await this.bit(value, 19, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 19 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit19be(value) {
        await this.bit(value, 19, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit20(value) {
        await this.bit(value, 20);
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit20le(value) {
        await this.bit(value, 20, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit20be(value) {
        await this.bit(value, 20, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit20(value) {
        await this.bit(value, 20, true);
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit20le(value) {
        await this.bit(value, 20, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 20 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit20be(value) {
        await this.bit(value, 20, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit21(value) {
        await this.bit(value, 21);
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit21le(value) {
        await this.bit(value, 21, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit21be(value) {
        await this.bit(value, 21, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit21(value) {
        await this.bit(value, 21, true);
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit21le(value) {
        await this.bit(value, 21, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 21 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit21be(value) {
        await this.bit(value, 21, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit22(value) {
        await this.bit(value, 22);
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit22le(value) {
        await this.bit(value, 22, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit22be(value) {
        await this.bit(value, 22, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit22(value) {
        await this.bit(value, 22, true);
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit22le(value) {
        await this.bit(value, 22, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 22 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit22be(value) {
        await this.bit(value, 22, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit23(value) {
        await this.bit(value, 23);
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit23le(value) {
        await this.bit(value, 23, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit23be(value) {
        await this.bit(value, 23, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit23(value) {
        await this.bit(value, 23, true);
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit23le(value) {
        await this.bit(value, 23, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 23 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit23be(value) {
        await this.bit(value, 23, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit24(value) {
        await this.bit(value, 24);
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit24le(value) {
        await this.bit(value, 24, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit24be(value) {
        await this.bit(value, 24, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit24(value) {
        await this.bit(value, 24, true);
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit24le(value) {
        await this.bit(value, 24, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 24 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit24be(value) {
        await this.bit(value, 24, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit25(value) {
        await this.bit(value, 25);
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit25le(value) {
        await this.bit(value, 25, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit25be(value) {
        await this.bit(value, 25, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit25(value) {
        await this.bit(value, 25, true);
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit25le(value) {
        await this.bit(value, 25, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 25 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit25be(value) {
        await this.bit(value, 25, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit26(value) {
        await this.bit(value, 26);
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit26le(value) {
        await this.bit(value, 26, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit26be(value) {
        await this.bit(value, 26, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit26(value) {
        await this.bit(value, 26, true);
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit26le(value) {
        await this.bit(value, 26, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 26 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit26be(value) {
        await this.bit(value, 26, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit27(value) {
        await this.bit(value, 27);
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit27le(value) {
        await this.bit(value, 27, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit27be(value) {
        await this.bit(value, 27, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit27(value) {
        await this.bit(value, 27, true);
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit27le(value) {
        await this.bit(value, 27, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 27 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit27be(value) {
        await this.bit(value, 27, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit28(value) {
        await this.bit(value, 28);
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit28le(value) {
        await this.bit(value, 28, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit28be(value) {
        await this.bit(value, 28, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit28(value) {
        await this.bit(value, 28, true);
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit28le(value) {
        await this.bit(value, 28, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 28 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit28be(value) {
        await this.bit(value, 28, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit29(value) {
        await this.bit(value, 29);
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit29le(value) {
        await this.bit(value, 29, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit29be(value) {
        await this.bit(value, 29, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit29(value) {
        await this.bit(value, 29, true);
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit29le(value) {
        await this.bit(value, 29, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 29 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit29be(value) {
        await this.bit(value, 29, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit30(value) {
        await this.bit(value, 30);
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit30le(value) {
        await this.bit(value, 30, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit30be(value) {
        await this.bit(value, 30, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit30(value) {
        await this.bit(value, 30, true);
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit30le(value) {
        await this.bit(value, 30, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 30 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit30be(value) {
        await this.bit(value, 30, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit31(value) {
        await this.bit(value, 31);
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit31le(value) {
        await this.bit(value, 31, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit31be(value) {
        await this.bit(value, 31, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit31(value) {
        await this.bit(value, 31, true);
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit31le(value) {
        await this.bit(value, 31, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 31 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit31be(value) {
        await this.bit(value, 31, true, "big");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit32(value) {
        await this.bit(value, 32);
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit32le(value) {
        await this.bit(value, 32, undefined, "little");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async bit32be(value) {
        await this.bit(value, 32, undefined, "big");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit32(value) {
        await this.bit(value, 32, true);
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit32le(value) {
        await this.bit(value, 32, true, "little");
    }
    ;
    /**
     * Bit field writer. Writes 32 bits.
     *
     * Note: When returning to a byte write, remaining bits are dropped.
     *
     * @param {number} value - value as int
     */
    async ubit32be(value) {
        await this.bit(value, 32, true, "big");
    }
    ;
    //
    // #region byte write
    //
    /**
     * Write byte.
     *
     * @param {number} value - value as int
     */
    async byte(value) {
        await this.writeByte(value);
    }
    ;
    /**
     * Write byte.
     *
     * @param {number} value - value as int
     */
    async int8(value) {
        await this.writeByte(value);
    }
    ;
    /**
     * Write unsigned byte.
     *
     * @param {number} value - value as int
     */
    async uint8(value) {
        await this.writeByte(value, true);
    }
    ;
    /**
     * Write unsigned byte.
     *
     * @param {number} value - value as int
     */
    async ubyte(value) {
        await this.writeByte(value, true);
    }
    ;
    //
    // #region short writes
    //
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     */
    async int16(value) {
        await this.writeInt16(value);
    }
    ;
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     */
    async short(value) {
        await this.writeInt16(value);
    }
    ;
    /**
     * Write int16.
     *
     * @param {number} value - value as int
     */
    async word(value) {
        await this.writeInt16(value);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async uint16(value) {
        await this.writeInt16(value, true);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async ushort(value) {
        await this.writeInt16(value, true);
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async uword(value) {
        await this.writeInt16(value, true);
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async int16be(value) {
        await this.writeInt16(value, false, "big");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async shortbe(value) {
        await this.writeInt16(value, false, "big");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async wordbe(value) {
        await this.writeInt16(value, false, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async uint16be(value) {
        await this.writeInt16(value, true, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async ushortbe(value) {
        await this.writeInt16(value, true, "big");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async uwordbe(value) {
        await this.writeInt16(value, true, "big");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async int16le(value) {
        await this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async shortle(value) {
        await this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write signed int16.
     *
     * @param {number} value - value as int
     */
    async wordle(value) {
        await this.writeInt16(value, false, "little");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async uint16le(value) {
        await this.writeInt16(value, true, "little");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async ushortle(value) {
        await this.writeInt16(value, true, "little");
    }
    ;
    /**
     * Write unsigned int16.
     *
     * @param {number} value - value as int
     */
    async uwordle(value) {
        await this.writeInt16(value, true, "little");
    }
    ;
    //
    // #region half float
    //
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    async half(value) {
        await this.writeHalfFloat(value);
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    async halffloat(value) {
        await this.writeHalfFloat(value);
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    async halffloatbe(value) {
        await this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    async halfbe(value) {
        await this.writeHalfFloat(value, "big");
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    async halffloatle(value) {
        await this.writeHalfFloat(value, "little");
    }
    ;
    /**
     * Writes half float.
     *
     * @param {number} value - value as int
     */
    async halfle(value) {
        await this.writeHalfFloat(value, "little");
    }
    ;
    //
    // #region int32 write
    //
    /**
     * Write int32.
     *
     * @param {number} value - value as int
     */
    async int(value) {
        await this.writeInt32(value);
    }
    ;
    /**
    * Write int32.
    *
    * @param {number} value - value as int
    */
    async int32(value) {
        await this.writeInt32(value);
    }
    ;
    /**
     * Write int32.
     *
     * @param {number} value - value as int
     */
    async double(value) {
        await this.writeInt32(value);
    }
    ;
    /**
     * Write int32.
     *
     * @param {number} value - value as int
     */
    async long(value) {
        await this.writeInt32(value);
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async uint32(value) {
        await this.writeInt32(value, true);
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async uint(value) {
        await this.writeInt32(value, true);
    }
    ;
    /**
    * Write unsigned int32.
    *
    * @param {number} value - value as int
    */
    async udouble(value) {
        await this.writeInt32(value, true);
    }
    ;
    /**
    * Write unsigned int32.
    *
    * @param {number} value - value as int
    */
    async ulong(value) {
        await this.writeInt32(value, true);
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async int32le(value) {
        await this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async intle(value) {
        await this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async doublele(value) {
        await this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async longle(value) {
        await this.writeInt32(value, false, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async uint32le(value) {
        await this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async uintle(value) {
        await this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async udoublele(value) {
        await this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async ulongle(value) {
        await this.writeInt32(value, true, "little");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async intbe(value) {
        await this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async int32be(value) {
        await this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async doublebe(value) {
        await this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write signed int32.
     *
     * @param {number} value - value as int
     */
    async longbe(value) {
        await this.writeInt32(value, false, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async writeUInt32BE(value) {
        await this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async uint32be(value) {
        await this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async uintbe(value) {
        await this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async udoublebe(value) {
        await this.writeInt32(value, true, "big");
    }
    ;
    /**
     * Write unsigned int32.
     *
     * @param {number} value - value as int
     */
    async ulongbe(value) {
        await this.writeInt32(value, true, "big");
    }
    ;
    //
    // #region float write
    //
    /**
    * Write float.
    *
    * @param {number} value - value as int
    */
    async float(value) {
        await this.writeFloat(value);
    }
    ;
    /**
     * Write float.
     *
     * @param {number} value - value as int
     */
    async floatle(value) {
        await this.writeFloat(value, "little");
    }
    ;
    /**
    * Write float.
    *
    * @param {number} value - value as int
    */
    async floatbe(value) {
        await this.writeFloat(value, "big");
    }
    ;
    //
    // #region int64 write
    //
    /**
     * Write 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async int64(value) {
        await this.writeInt64(value);
    }
    ;
    /**
    * Write 64 bit integer.
    *
    * @param {BigValue} value - value as int
    */
    async quad(value) {
        await this.writeInt64(value);
    }
    ;
    /**
     * Write 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async bigint(value) {
        await this.writeInt64(value);
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async uint64(value) {
        await this.writeInt64(value, true);
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async ubigint(value) {
        await this.writeInt64(value, true);
    }
    ;
    /**
    * Write unsigned 64 bit integer.
    *
    * @param {BigValue} value - value as int
    */
    async uquad(value) {
        await this.writeInt64(value, true);
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async int64le(value) {
        await this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async bigintle(value) {
        await this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async quadle(value) {
        await this.writeInt64(value, false, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async uint64le(value) {
        await this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async ubigintle(value) {
        await this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async uquadle(value) {
        await this.writeInt64(value, true, "little");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async int64be(value) {
        await this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async bigintbe(value) {
        await this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write signed 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async quadbe(value) {
        await this.writeInt64(value, false, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async uint64be(value) {
        await this.writeInt64(value, true, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async ubigintbe(value) {
        await this.writeInt64(value, true, "big");
    }
    ;
    /**
     * Write unsigned 64 bit integer.
     *
     * @param {BigValue} value - value as int
     */
    async uquadbe(value) {
        await this.writeInt64(value, true, "big");
    }
    ;
    //
    // #region doublefloat
    //
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    async doublefloat(value) {
        await this.writeDoubleFloat(value);
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    async dfloat(value) {
        await this.writeDoubleFloat(value);
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    async dfloatbe(value) {
        await this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    async doublefloatbe(value) {
        await this.writeDoubleFloat(value, "big");
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    async dfloatle(value) {
        await this.writeDoubleFloat(value, "little");
    }
    ;
    /**
     * Writes double float.
     *
     * @param {number} value - value as int
     */
    async doublefloatle(value) {
        await this.writeDoubleFloat(value, "little");
    }
    ;
    //
    // #region string
    //
    /**
    * Writes string, use options object for different types.
    *
    * @param {string} string - text string
    * @param {stringOptions?} options
    * @param {stringOptions["length"]?} options.length - for fixed length, non-terminate value utf strings
    * @param {stringOptions["stringType"]?} options.stringType - ascii, utf-8, utf-16, utf-32, pascal, wide-pascal or double-wide-pascal
    * @param {stringOptions["terminateValue"]?} options.terminateValue - only with stringType: "utf"
    * @param {stringOptions["lengthWriteSize"]?} options.lengthWriteSize - for pascal strings. 1, 2 or 4 byte length write size
    * @param {stringOptions["encoding"]?} options.encoding - TextEncoder accepted types
    * @param {stringOptions["endian"]?} options.endian - for utf-16, utf-32, wide-pascal or double-wide-pascal
    */
    async string(string, options) {
        return await this.writeString(string, options);
    }
    ;
    /**
    * Writes string using setting from .strDefaults
    *
    * Default is ``utf-8``
    *
    * @param {string} string - text string
    */
    async str(string) {
        await this.writeString(string, this.strDefaults);
    }
    ;
    /**
    * Writes UTF-8 (C) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async utf8string(string, length, terminateValue) {
        return await this.string(string, { stringType: "utf-8", encoding: "utf-8", length: length, terminateValue: terminateValue });
    }
    ;
    /**
    * Writes UTF-8 (C) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async cstring(string, length, terminateValue) {
        return await this.utf8string(string, length, terminateValue);
    }
    ;
    /**
    * Writes ANSI string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async ansistring(string, length, terminateValue) {
        return await this.string(string, { stringType: "utf-8", encoding: "windows-1252", length: length, terminateValue: terminateValue });
    }
    ;
    /**
    * Writes latin1 string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async latin1string(string, length, terminateValue) {
        return await this.string(string, { stringType: "utf-8", encoding: "iso-8859-1", length: length, terminateValue: terminateValue });
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["endian"]} endian - for wide-pascal and utf-16
    */
    async utf16string(string, length, terminateValue, endian) {
        return await this.string(string, { stringType: "utf-16", encoding: "utf-16", length: length, terminateValue: terminateValue, endian: endian });
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["endian"]} endian - for wide-pascal and utf-16
    */
    async unistring(string, length, terminateValue, endian) {
        return await this.utf16string(string, length, terminateValue, endian);
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async utf16stringle(string, length, terminateValue) {
        return await this.unistring(string, length, terminateValue, "little");
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async unistringle(string, length, terminateValue) {
        return await this.utf16stringle(string, length, terminateValue);
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async utf16stringbe(string, length, terminateValue) {
        return await this.unistring(string, length, terminateValue, "big");
    }
    ;
    /**
    * Writes UTF-16 (Unicode) string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async unistringbe(string, length, terminateValue) {
        return await this.utf16stringbe(string, length, terminateValue);
    }
    ;
    /**
    * Writes UTF-32 (Unicode) string.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    * @param {stringOptions["endian"]} endian - for wide-pascal and utf-16
    */
    async utf32string(string, length, terminateValue, endian) {
        return await this.string(string, { stringType: "utf-32", encoding: "utf-32", length: length, terminateValue: terminateValue, endian: endian });
    }
    ;
    /**
    * Writes UTF-32 (Unicode) string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async utf32stringle(string, length, terminateValue) {
        return await this.utf32string(string, length, terminateValue, "little");
    }
    ;
    /**
    * Writes UTF-32 (Unicode) string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["length"]} length - for fixed length utf strings
    * @param {stringOptions["terminateValue"]} terminateValue - for non-fixed length utf strings
    */
    async utf32stringbe(string, length, terminateValue) {
        return await this.utf32string(string, length, terminateValue, "big");
    }
    ;
    /**
    * Writes Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["endian"]} endian - ``big`` or ``little`` for 2 or 4 byte length write size
    */
    async pstring(string, lengthWriteSize, endian) {
        return await this.string(string, { stringType: "pascal", encoding: "utf-8", lengthWriteSize: lengthWriteSize, endian: endian });
    }
    ;
    /**
    * Writes Pascal string 1 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little`` for 2 or 4 byte length write size
    */
    async pstring1(string, endian) {
        return await this.pstring(string, 1, endian);
    }
    ;
    /**
    * Writes Pascal string 1 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async pstring1le(string) {
        return await this.pstring1(string, "little");
    }
    ;
    /**
    * Writes Pascal string 1 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async pstring1be(string) {
        return await this.pstring1(string, "big");
    }
    ;
    /**
    * Writes Pascal string 2 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async pstring2(string, endian) {
        return await this.pstring(string, 2, endian);
    }
    ;
    /**
    * Writes Pascal string 2 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async pstring2le(string) {
        return await this.pstring2(string, "little");
    }
    ;
    /**
    * Writes Pascal string 2 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async pstring2be(string) {
        return await this.pstring2(string, "big");
    }
    ;
    /**
    * Writes Pascal string 4 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async pstring4(string, endian) {
        return await this.pstring(string, 4, endian);
    }
    ;
    /**
    * Writes Pascal string 4 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async pstring4le(string) {
        return await this.pstring4(string, "little");
    }
    ;
    /**
    * Writes Pascal string 4 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async pstring4be(string) {
        return await this.pstring4(string, "big");
    }
    ;
    /**
    * Writes Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async wpstring(string, lengthWriteSize, endian) {
        return await this.string(string, { stringType: "wide-pascal", encoding: "utf-16", lengthWriteSize: lengthWriteSize, endian: endian });
    }
    ;
    /**
    * Writes Wide Pascal string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    async wpstringle(string, lengthWriteSize) {
        return await this.wpstring(string, lengthWriteSize, "little");
    }
    ;
    /**
    * Writes Wide Pascal string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    async wpstringbe(string, lengthWriteSize) {
        return await this.wpstring(string, lengthWriteSize, "big");
    }
    ;
    /**
    * Writes Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async wpstring1(string, endian) {
        return await this.wpstring(string, 1, endian);
    }
    ;
    /**
    * Writes Wide Pascal string 1 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async wpstring1be(string) {
        return await this.wpstring1(string, "little");
    }
    ;
    /**
    * Writes Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async wpstring1le(string) {
        return await this.wpstring1(string, "big");
    }
    ;
    /**
    * Writes Wide Pascal string 2 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async wpstring2(string, endian) {
        return await this.wpstring(string, 2, endian);
    }
    ;
    /**
    * Writes Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async wpstring2le(string) {
        return await this.wpstring2(string, "little");
    }
    ;
    /**
    * Writes Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async wpstring2be(string) {
        return await this.wpstring2(string, "big");
    }
    ;
    /**
    * Writes Wide Pascal string 4 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async wpstring4(string, endian) {
        return await this.wpstring(string, 4, endian);
    }
    ;
    /**
    * Writes Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async wpstring4le(string) {
        return await this.wpstring4(string, "little");
    }
    ;
    /**
    * Writes Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async wpstring4be(string) {
        return await this.wpstring4(string, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async dwpstring(string, lengthWriteSize, endian) {
        return await this.string(string, { stringType: "double-wide-pascal", encoding: "utf-32", lengthWriteSize: lengthWriteSize, endian: endian });
    }
    ;
    /**
    * Writes Double Wide Pascal string in little endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    async dwpstringle(string, lengthWriteSize) {
        return await this.dwpstring(string, lengthWriteSize, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string in big endian order.
    *
    * @param {string} string - text string
    * @param {stringOptions["lengthWriteSize"]} lengthWriteSize - 1, 2 or 4 byte length write size (default 1)
    */
    async dwpstringbe(string, lengthWriteSize) {
        return await this.dwpstring(string, lengthWriteSize, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async dwpstring1(string, endian) {
        return await this.dwpstring(string, 1, endian);
    }
    ;
    /**
    * Writes Double Wide Pascal string 1 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async dwpstring1le(string) {
        return await this.dwpstring1(string, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string 1 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async dwpstring1be(string) {
        return await this.dwpstring1(string, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string 2 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async dwpstring2(string, endian) {
        return await this.dwpstring(string, 2, endian);
    }
    ;
    /**
    * Writes Double Wide Pascal string 2 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async dwpstring2le(string) {
        return await this.dwpstring2(string, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string 2 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async dwpstring2be(string) {
        return await this.dwpstring2(string, "big");
    }
    ;
    /**
    * Writes Double Wide Pascal string 4 byte length read.
    *
    * @param {string} string - text string
    * @param {stringOptions["endian"]} endian - ``big`` or ``little``
    */
    async dwpstring4(string, endian) {
        return await this.dwpstring(string, 4, endian);
    }
    ;
    /**
    * Writes Double Wide Pascal string 4 byte length read in little endian order.
    *
    * @param {string} string - text string
    */
    async dwpstring4le(string) {
        return await this.dwpstring4(string, "little");
    }
    ;
    /**
    * Writes Double Wide Pascal string 4 byte length read in big endian order.
    *
    * @param {string} string - text string
    */
    async dwpstring4be(string) {
        return await this.dwpstring4(string, "big");
    }
    ;
}

// node import
BiReader.fs = fs;
BiWriter.fs = fs;
BiBase.fs = fs;
BiReaderAsync.fs = fsp;
BiWriterAsync.fs = fsp;
BiBaseAsync.fs = fsp;

const ciphers = crypto.getCiphers();
/**
 * Random Xor Shift RNG. Can seed with number, a Uint8Array or Buffer of 4 bytes
 * ```javascript
 * const seed; //number, Uint8Array or Buffer of 4 bytes
 * const rng = new RandomXorShift(seed);
 * const random_int = rng.random_int();
 * ```
 * @param {number|Uint8Array|Buffer} seed - Can seeded with a number or a Uint8Array or Buffer of 4 bytes
 */
class RandomXorShift {
    constructor(seed) {
        var s;
        const mt = [0, 0, 0, 0];
        if (seed == undefined) {
            seed = new Date().getTime();
        }
        if (typeof Buffer !== 'undefined' && seed instanceof Buffer) {
            if (seed.length < 4) {
                throw new Error("Must be a seed Buffer of 4 bytes");
            }
            mt[0] = seed.readUInt32LE() >>> 0;
        }
        else {
            if (seed instanceof Uint8Array) {
                if (seed.length < 4) {
                    throw new Error("Must be a seed Uint8Array of 4 bytes");
                }
                mt[0] = ((seed[3] << 24) | (seed[2] << 16) | (seed[1] << 8) | seed[0]);
            }
            else {
                if (typeof seed == "number") {
                    mt[0] = seed >>> 0;
                }
            }
        }
        for (var i = 1; i < 5; i++) {
            s = mt[i - 1] ^ (mt[i - 1] >>> 30);
            mt[i] = (((((s & 0xffff0000) >>> 16) * 1812433253) << 16) + (s & 0x0000ffff) * 1812433253) + (i - 1);
            mt[i] >>>= 0;
        }
        mt.shift();
        var result = new Uint8Array(16);
        mt.forEach((e, i) => {
            result[(i * 4)] = e & 0xFF;
            result[(i * 4) + 1] = (e >> 8) & 0xFF;
            result[(i * 4) + 2] = (e >> 16) & 0xFF;
            result[(i * 4) + 3] = (e >> 24) & 0xFF;
        });
        this.mt = result;
    }
    /**
     * Generate a random unsigned 32 bit integer
     * @returns number
     */
    random_int() {
        let v1 = ((this.mt[3] << 24) | (this.mt[2] << 16) | (this.mt[1] << 8) | this.mt[0]);
        let v4 = ((this.mt[15] << 24) | (this.mt[14] << 16) | (this.mt[13] << 8) | this.mt[12]);
        let comp_1 = (v4 ^ (v4 >>> 19) ^ v1 ^ (v1 << 11) ^ ((v1 ^ (v1 << 11)) >>> 8)) >>> 0;
        let new_value = new Uint8Array(4);
        new_value[0] = comp_1 & 0xFF;
        new_value[1] = (comp_1 >> 8) & 0xFF;
        new_value[2] = (comp_1 >> 16) & 0xFF;
        new_value[3] = (comp_1 >> 24) & 0xFF;
        const shift = this.mt.subarray(4, 16);
        var newBuffer = new Uint8Array([...shift, ...new_value]);
        this.mt = newBuffer;
        return comp_1;
    }
}
class Crypt {
    constructor(key) {
        this.cipher = null;
        this.decipher = null;
        this.hashArray = ['aria-256-cbc', 'aes-256-cbc', 'camellia-256-cbc'];
        this.hash = "";
        this.useFallback = false;
        this.fallback = null;
        if (key == 0 || key == undefined) {
            const rng = new RandomXorShift();
            this.key = rng.random_int();
        }
        else {
            this.key = key >>> 0;
        }
        const hash = this.key & 0x3;
        const spin = ((this.key >>> 2) & 0x3F) >>> 0;
        const value = ((this.key >>> 8) & 0xFFFFFF) >>> 0;
        const rng = new RandomXorShift(value);
        for (let i = 0; i < spin; i++)
            rng.random_int();
        const keyBuff = new BiWriter(Buffer.alloc(32));
        const iv = new BiWriter(Buffer.alloc(16));
        for (let i = 0; i < 8; i++) {
            keyBuff.uint32 = rng.random_int();
        }
        for (let i = 0; i < 4; i++) {
            iv.uint32 = rng.random_int();
        }
        this.hash = this.hashArray[hash % this.hashArray.length];
        if ((ciphers.findIndex((x) => x === this.hash) == -1)) {
            this.useFallback = true;
        }
        this.keyBuff = keyBuff.data;
        this.ivBuffer = iv.data;
    }
    ;
    fallbackCipher() {
        var crypt;
        switch (this.hash) {
            case "aes-256-cbc":
                crypt = new AES();
                break;
            case "aria-256-cbc":
                crypt = new ARIA();
                break;
            case "camellia-256-cbc":
                crypt = new CAMELLIA();
                break;
            default:
                throw new Error("Did not find cipher.");
        }
        crypt.set_key(this.keyBuff);
        crypt.set_iv(this.ivBuffer);
        this.fallback = crypt;
    }
    ;
    encrypt(data) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback?.encrypt(data);
        }
        if (this.cipher == null) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return Buffer.concat([this.cipher.update(data), this.cipher.final()]);
    }
    ;
    decrypt(data) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback?.decrypt(data);
        }
        if (this.decipher == null) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return Buffer.concat([this.decipher.update(data), this.decipher.final()]);
    }
    ;
    encrypt_block(data, final) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback?.encrypt_block(data, final);
        }
        if (this.cipher == null) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.cipher.update(data);
    }
    ;
    decrypt_block(data, final) {
        if (this.useFallback) {
            if (this.fallback == null)
                this.fallbackCipher();
            return this.fallback?.decrypt_block(data, final);
        }
        if (this.decipher == null) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.decipher.update(data);
    }
    ;
    encrypt_final() {
        if (this.useFallback) {
            return Buffer.alloc(0);
        }
        if (this.cipher == null) {
            this.cipher = crypto.createCipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.cipher.final();
    }
    ;
    decrypt_final() {
        if (this.useFallback) {
            return Buffer.alloc(0);
        }
        if (this.decipher == null) {
            this.decipher = crypto.createDecipheriv(this.hash, this.keyBuff, this.ivBuffer);
        }
        return this.decipher.final();
    }
    ;
}
const CRC_TABLE = new Int32Array([
    0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3,
    0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91,
    0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
    0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9, 0xfa0f3d63, 0x8d080df5,
    0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
    0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
    0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599, 0xb8bda50f,
    0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924, 0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d,
    0x76dc4190, 0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
    0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
    0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457,
    0x65b0d9c6, 0x12b7e950, 0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
    0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb,
    0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9,
    0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
    0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad,
    0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683,
    0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
    0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb, 0x196c3671, 0x6e6b06e7,
    0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
    0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
    0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef, 0x4669be79,
    0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236, 0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f,
    0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
    0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
    0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21,
    0x86d3d2d4, 0xf1d4e242, 0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
    0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45,
    0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db,
    0xaed16a4a, 0xd9d65adc, 0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
    0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bf,
    0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d,
]);
/**
 * Cyclic Redundancy Check 32.
 *
 * @param {Buffer} current - Message Buffer
 * @param {number?} previous - previous hash
 * @returns {number}
 */
function CRC32(current, previous) {
    if (!(current instanceof Buffer)) {
        throw new Error("Message must be a Buffer.");
    }
    let crc = previous === 0 ? 0 : ~~previous ^ -1;
    for (let index = 0; index < current.length; index++) {
        crc = CRC_TABLE[(crc ^ current[index]) & 0xff] ^ (crc >>> 8);
    }
    return crc ^ -1;
}
function xor(buf1, buf2) {
    let number = -1;
    for (let i = 0; i < buf1.length; i++) {
        const b = buf1[i];
        if (number != buf2.length - 1) {
            number = number + 1;
        }
        else {
            number = 0;
        }
        buf1[i] = b ^ buf2[number];
    }
    return buf1;
}
function align(a, n) {
    var a = a % n;
    if (a) {
        return (n - a);
    }
    else {
        return 0;
    }
}
function removePKCSPadding(buffer, number, PKCS = false) {
    const lastByte = buffer[buffer.length - 1];
    if (PKCS == true) {
        if (lastByte < 1 || lastByte > 17) {
            return buffer;
        }
        var len = buffer.length;
        var removed = 0;
        for (let i = buffer.length - 1; i > 0; i--) {
            if (buffer[i] == lastByte) {
                len--;
                removed++;
            }
        }
        if (removed == lastByte) {
            buffer = buffer.subarray(0, len);
        }
        return buffer;
    }
    else if (lastByte != number) {
        return buffer;
    }
    else {
        var len = buffer.length;
        for (let i = buffer.length - 1; i > 0; i--) {
            if (buffer[i] == number) {
                len--;
            }
        }
        return buffer.subarray(0, len);
    }
}
function padd_block(data) {
    const block_size = 16;
    if (data.length % block_size != 0) {
        var padd_value = block_size - (data.length % block_size);
        var paddbuffer = Buffer.alloc(padd_value, padd_value & 0xFF);
        data = Buffer.concat([data, paddbuffer]);
    }
    return data;
}
class AES {
    AES_SubBytes(state, sbox) {
        for (var i = 0; i < 16; i++) {
            state[i] = sbox[state[i]];
        }
    }
    AES_AddRoundKey(state, rkey) {
        for (var i = 0; i < 16; i++) {
            state[i] ^= rkey[i];
        }
    }
    AES_ShiftRows(state, shifttab) {
        var h = new Array().concat(state);
        for (var i = 0; i < 16; i++) {
            state[i] = h[shifttab[i]];
        }
    }
    AES_MixColumns(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0], s1 = state[i + 1];
            var s2 = state[i + 2], s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            state[i + 0] ^= h ^ this.AES_xtime[s0 ^ s1];
            state[i + 1] ^= h ^ this.AES_xtime[s1 ^ s2];
            state[i + 2] ^= h ^ this.AES_xtime[s2 ^ s3];
            state[i + 3] ^= h ^ this.AES_xtime[s3 ^ s0];
        }
    }
    AES_MixColumns_Inv(state) {
        for (var i = 0; i < 16; i += 4) {
            var s0 = state[i + 0], s1 = state[i + 1];
            var s2 = state[i + 2], s3 = state[i + 3];
            var h = s0 ^ s1 ^ s2 ^ s3;
            var xh = this.AES_xtime[h];
            var h1 = this.AES_xtime[this.AES_xtime[xh ^ s0 ^ s2]] ^ h;
            var h2 = this.AES_xtime[this.AES_xtime[xh ^ s1 ^ s3]] ^ h;
            state[i + 0] ^= h1 ^ this.AES_xtime[s0 ^ s1];
            state[i + 1] ^= h2 ^ this.AES_xtime[s1 ^ s2];
            state[i + 2] ^= h1 ^ this.AES_xtime[s2 ^ s3];
            state[i + 3] ^= h2 ^ this.AES_xtime[s3 ^ s0];
        }
    }
    constructor() {
        this.key_set = false;
        this.iv_set = false;
        this.AES_Sbox = new Array(99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22);
        this.AES_ShiftRowTab = new Array(0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11);
        this.AES_Sbox_Inv = new Array(256);
        this.AES_xtime = new Array(256);
        this.AES_ShiftRowTab_Inv = new Array(16);
    }
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer} key_data - ```Buffer```
     */
    set_key(key_data) {
        var kl = key_data.length, ks, Rcon = 1;
        switch (kl) {
            case 16:
                ks = 16 * (10 + 1);
                break;
            case 24:
                ks = 16 * (12 + 1);
                break;
            case 32:
                ks = 16 * (14 + 1);
                break;
            default:
                throw Error("Only key lengths of 16, 24 or 32 bytes allowed!");
        }
        const key = new Array(key_data.length);
        for (let i = 0; i < key_data.length; i++) {
            key[i] = key_data[i];
        }
        this.key = key;
        for (var i = kl; i < ks; i += 4) {
            var temp = key.slice(i - 4, i);
            if (i % kl == 0) {
                temp = new Array(this.AES_Sbox[temp[1]] ^ Rcon, this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]], this.AES_Sbox[temp[0]]);
                if ((Rcon <<= 1) >= 256)
                    Rcon ^= 0x11b;
            }
            else if ((kl > 24) && (i % kl == 16))
                temp = new Array(this.AES_Sbox[temp[0]], this.AES_Sbox[temp[1]], this.AES_Sbox[temp[2]], this.AES_Sbox[temp[3]]);
            for (var j = 0; j < 4; j++)
                key[i + j] = key[i + j - kl] ^ temp[j];
        }
        this.key_set = true;
        //setup
        for (var z = 0; z < 256; z++) {
            this.AES_Sbox_Inv[this.AES_Sbox[z]] = z;
        }
        for (var z = 0; z < 16; z++) {
            this.AES_ShiftRowTab_Inv[this.AES_ShiftRowTab[z]] = z;
        }
        for (var z = 0; z < 128; z++) {
            this.AES_xtime[z] = z << 1;
            this.AES_xtime[128 + z] = (z << 1) ^ 0x1b;
        }
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer} iv - ```Buffer```
     */
    set_iv(iv) {
        if (iv) {
            if (iv.length != 16) {
                throw Error("Enter a vaild 16 byte IV for CBC mode");
            }
            else {
                this.iv = iv;
                this.iv_set = true;
            }
        }
        else {
            throw Error("Enter a vaild 16 byte IV for CBC mode");
        }
    }
    ;
    encrypt_block(start_chunk, last_block) {
        //check if IV is set, if so runs CBC
        let block = start_chunk;
        if (last_block) {
            block = padd_block(start_chunk);
        }
        if (this.iv_set == true) {
            block = xor(block, this.iv);
        }
        const block_data = new Array(16);
        for (let i = 0; i < 16; i++) {
            block_data[i] = block[i];
        }
        var key = this.key;
        var l = key.length;
        this.AES_AddRoundKey(block_data, key.slice(0, 16));
        for (var i = 16; i < l - 16; i += 16) {
            this.AES_SubBytes(block_data, this.AES_Sbox);
            this.AES_ShiftRows(block_data, this.AES_ShiftRowTab);
            this.AES_MixColumns(block_data);
            this.AES_AddRoundKey(block_data, key.slice(i, i + 16));
        }
        this.AES_SubBytes(block_data, this.AES_Sbox);
        this.AES_ShiftRows(block_data, this.AES_ShiftRowTab);
        this.AES_AddRoundKey(block_data, key.slice(i, l));
        var block_out = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
            block_out[i] = block_data[i];
        }
        if (this.iv_set == true) {
            this.iv = block_out;
        }
        return block_out;
    }
    ;
    decrypt_block(start_chunk, last_block) {
        let block = start_chunk;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = block;
        const block_data = new Array(16);
        for (let i = 0; i < 16; i++) {
            block_data[i] = block[i];
        }
        var key = this.key;
        var l = key.length;
        this.AES_AddRoundKey(block_data, key.slice(l - 16, l));
        this.AES_ShiftRows(block_data, this.AES_ShiftRowTab_Inv);
        this.AES_SubBytes(block_data, this.AES_Sbox_Inv);
        for (var i = l - 32; i >= 16; i -= 16) {
            this.AES_AddRoundKey(block_data, key.slice(i, i + 16));
            this.AES_MixColumns_Inv(block_data);
            this.AES_ShiftRows(block_data, this.AES_ShiftRowTab_Inv);
            this.AES_SubBytes(block_data, this.AES_Sbox_Inv);
        }
        this.AES_AddRoundKey(block_data, key.slice(0, 16));
        var block_out = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
            block_out[i] = block_data[i];
        }
        var return_buffer = block_out;
        if (this.iv_set == true) {
            // @ts-ignore
            return_buffer = xor(block_out, this.iv);
        }
        if (last_block) {
            var padd_value = align(return_buffer.length, 16);
            return removePKCSPadding(return_buffer, padd_value, true);
        }
        return return_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer```
     */
    encrypt(data_in, padding = 0) {
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer} data_in - `Buffer`
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns `Buffer`
     */
    decrypt(data_in, remove_padding = true) {
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            var return_block = this.decrypt_block(block);
            if ((remove_padding != false) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
class ARIA {
    constructor() {
        // Constants
        this.ARIA_BLOCK_SIZE = 16;
        // S-box 1
        this.sb1 = Buffer.from([
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        ]);
        // S-box 2
        this.sb2 = Buffer.from([
            0xE2, 0x4E, 0x54, 0xFC, 0x94, 0xC2, 0x4A, 0xCC, 0x62, 0x0D, 0x6A, 0x46, 0x3C, 0x4D, 0x8B, 0xD1,
            0x5E, 0xFA, 0x64, 0xCB, 0xB4, 0x97, 0xBE, 0x2B, 0xBC, 0x77, 0x2E, 0x03, 0xD3, 0x19, 0x59, 0xC1,
            0x1D, 0x06, 0x41, 0x6B, 0x55, 0xF0, 0x99, 0x69, 0xEA, 0x9C, 0x18, 0xAE, 0x63, 0xDF, 0xE7, 0xBB,
            0x00, 0x73, 0x66, 0xFB, 0x96, 0x4C, 0x85, 0xE4, 0x3A, 0x09, 0x45, 0xAA, 0x0F, 0xEE, 0x10, 0xEB,
            0x2D, 0x7F, 0xF4, 0x29, 0xAC, 0xCF, 0xAD, 0x91, 0x8D, 0x78, 0xC8, 0x95, 0xF9, 0x2F, 0xCE, 0xCD,
            0x08, 0x7A, 0x88, 0x38, 0x5C, 0x83, 0x2A, 0x28, 0x47, 0xDB, 0xB8, 0xC7, 0x93, 0xA4, 0x12, 0x53,
            0xFF, 0x87, 0x0E, 0x31, 0x36, 0x21, 0x58, 0x48, 0x01, 0x8E, 0x37, 0x74, 0x32, 0xCA, 0xE9, 0xB1,
            0xB7, 0xAB, 0x0C, 0xD7, 0xC4, 0x56, 0x42, 0x26, 0x07, 0x98, 0x60, 0xD9, 0xB6, 0xB9, 0x11, 0x40,
            0xEC, 0x20, 0x8C, 0xBD, 0xA0, 0xC9, 0x84, 0x04, 0x49, 0x23, 0xF1, 0x4F, 0x50, 0x1F, 0x13, 0xDC,
            0xD8, 0xC0, 0x9E, 0x57, 0xE3, 0xC3, 0x7B, 0x65, 0x3B, 0x02, 0x8F, 0x3E, 0xE8, 0x25, 0x92, 0xE5,
            0x15, 0xDD, 0xFD, 0x17, 0xA9, 0xBF, 0xD4, 0x9A, 0x7E, 0xC5, 0x39, 0x67, 0xFE, 0x76, 0x9D, 0x43,
            0xA7, 0xE1, 0xD0, 0xF5, 0x68, 0xF2, 0x1B, 0x34, 0x70, 0x05, 0xA3, 0x8A, 0xD5, 0x79, 0x86, 0xA8,
            0x30, 0xC6, 0x51, 0x4B, 0x1E, 0xA6, 0x27, 0xF6, 0x35, 0xD2, 0x6E, 0x24, 0x16, 0x82, 0x5F, 0xDA,
            0xE6, 0x75, 0xA2, 0xEF, 0x2C, 0xB2, 0x1C, 0x9F, 0x5D, 0x6F, 0x80, 0x0A, 0x72, 0x44, 0x9B, 0x6C,
            0x90, 0x0B, 0x5B, 0x33, 0x7D, 0x5A, 0x52, 0xF3, 0x61, 0xA1, 0xF7, 0xB0, 0xD6, 0x3F, 0x7C, 0x6D,
            0xED, 0x14, 0xE0, 0xA5, 0x3D, 0x22, 0xB3, 0xF8, 0x89, 0xDE, 0x71, 0x1A, 0xAF, 0xBA, 0xB5, 0x81
        ]);
        // S-box 3
        this.sb3 = Buffer.from([
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
        ]);
        // S-box 4
        this.sb4 = Buffer.from([
            0x30, 0x68, 0x99, 0x1B, 0x87, 0xB9, 0x21, 0x78, 0x50, 0x39, 0xDB, 0xE1, 0x72, 0x09, 0x62, 0x3C,
            0x3E, 0x7E, 0x5E, 0x8E, 0xF1, 0xA0, 0xCC, 0xA3, 0x2A, 0x1D, 0xFB, 0xB6, 0xD6, 0x20, 0xC4, 0x8D,
            0x81, 0x65, 0xF5, 0x89, 0xCB, 0x9D, 0x77, 0xC6, 0x57, 0x43, 0x56, 0x17, 0xD4, 0x40, 0x1A, 0x4D,
            0xC0, 0x63, 0x6C, 0xE3, 0xB7, 0xC8, 0x64, 0x6A, 0x53, 0xAA, 0x38, 0x98, 0x0C, 0xF4, 0x9B, 0xED,
            0x7F, 0x22, 0x76, 0xAF, 0xDD, 0x3A, 0x0B, 0x58, 0x67, 0x88, 0x06, 0xC3, 0x35, 0x0D, 0x01, 0x8B,
            0x8C, 0xC2, 0xE6, 0x5F, 0x02, 0x24, 0x75, 0x93, 0x66, 0x1E, 0xE5, 0xE2, 0x54, 0xD8, 0x10, 0xCE,
            0x7A, 0xE8, 0x08, 0x2C, 0x12, 0x97, 0x32, 0xAB, 0xB4, 0x27, 0x0A, 0x23, 0xDF, 0xEF, 0xCA, 0xD9,
            0xB8, 0xFA, 0xDC, 0x31, 0x6B, 0xD1, 0xAD, 0x19, 0x49, 0xBD, 0x51, 0x96, 0xEE, 0xE4, 0xA8, 0x41,
            0xDA, 0xFF, 0xCD, 0x55, 0x86, 0x36, 0xBE, 0x61, 0x52, 0xF8, 0xBB, 0x0E, 0x82, 0x48, 0x69, 0x9A,
            0xE0, 0x47, 0x9E, 0x5C, 0x04, 0x4B, 0x34, 0x15, 0x79, 0x26, 0xA7, 0xDE, 0x29, 0xAE, 0x92, 0xD7,
            0x84, 0xE9, 0xD2, 0xBA, 0x5D, 0xF3, 0xC5, 0xB0, 0xBF, 0xA4, 0x3B, 0x71, 0x44, 0x46, 0x2B, 0xFC,
            0xEB, 0x6F, 0xD5, 0xF6, 0x14, 0xFE, 0x7C, 0x70, 0x5A, 0x7D, 0xFD, 0x2F, 0x18, 0x83, 0x16, 0xA5,
            0x91, 0x1F, 0x05, 0x95, 0x74, 0xA9, 0xC1, 0x5B, 0x4A, 0x85, 0x6D, 0x13, 0x07, 0x4F, 0x4E, 0x45,
            0xB2, 0x0F, 0xC9, 0x1C, 0xA6, 0xBC, 0xEC, 0x73, 0x90, 0x7B, 0xCF, 0x59, 0x8F, 0xA1, 0xF9, 0x2D,
            0xF2, 0xB1, 0x00, 0x94, 0x37, 0x9F, 0xD0, 0x2E, 0x9C, 0x6E, 0x28, 0x3F, 0x80, 0xF0, 0x3D, 0xD3,
            0x25, 0x8A, 0xB5, 0xE7, 0x42, 0xB3, 0xC7, 0xEA, 0xF7, 0x4C, 0x11, 0x33, 0x03, 0xA2, 0xAC, 0x60
        ]);
        // Key scheduling constants
        this.c = new Uint32Array([
            0x517CC1B7, 0x27220A94, 0xFE13ABE8, 0xFA9A6EE0, 0x6DB14ACC, 0x9E21C820,
            0xFF28B1D5, 0xEF5DE2B0, 0xDB92371D, 0x2126E970, 0x03249775, 0x04E8C90E
        ]);
        this.nr = 0; // Number of rounds
        this.ek = new Uint32Array(68); // Encryption round keys - Max size for 256-bit key (17 rounds * 4)
        this.dk = new Uint32Array(68); // Decryption round keys
        this.key_set = false;
        this.iv_set = false;
    }
    ;
    // Utility functions
    load32BE(data, offset) {
        return (((data[offset] << 24) |
            (data[offset + 1] << 16) |
            (data[offset + 2] << 8) |
            data[offset + 3]) >>> 0);
    }
    ;
    store32BE(value, data, offset) {
        data[offset] = (value >>> 24) & 0xFF;
        data[offset + 1] = (value >>> 16) & 0xFF;
        data[offset + 2] = (value >>> 8) & 0xFF;
        data[offset + 3] = value & 0xFF;
    }
    ;
    mov128(b, a) {
        b[0] = a[0];
        b[1] = a[1];
        b[2] = a[2];
        b[3] = a[3];
    }
    ;
    xor128(b, a) {
        b[0] ^= a[0];
        b[1] ^= a[1];
        b[2] ^= a[2];
        b[3] ^= a[3];
    }
    ;
    rol128(b, a, n) {
        const shift = n % 32;
        const wordShift = Math.floor(n / 32);
        for (let i = 0; i < 4; i++) {
            const idx1 = (wordShift + i) % 4;
            const idx2 = (wordShift + i + 1) % 4;
            b[i] = ((a[idx1] << shift) | (a[idx2] >>> (32 - shift))) >>> 0;
        }
    }
    ;
    getByte(x, n) {
        return (x[Math.floor(n / 4)] >>> ((3 - (n % 4)) * 8)) & 0xFF;
    }
    ;
    sl1(b, a) {
        b[0] = (this.sb1[this.getByte(a, 0)] << 24) | (this.sb2[this.getByte(a, 1)] << 16) | (this.sb3[this.getByte(a, 2)] << 8) | this.sb4[this.getByte(a, 3)];
        b[1] = (this.sb1[this.getByte(a, 4)] << 24) | (this.sb2[this.getByte(a, 5)] << 16) | (this.sb3[this.getByte(a, 6)] << 8) | this.sb4[this.getByte(a, 7)];
        b[2] = (this.sb1[this.getByte(a, 8)] << 24) | (this.sb2[this.getByte(a, 9)] << 16) | (this.sb3[this.getByte(a, 10)] << 8) | this.sb4[this.getByte(a, 11)];
        b[3] = (this.sb1[this.getByte(a, 12)] << 24) | (this.sb2[this.getByte(a, 13)] << 16) | (this.sb3[this.getByte(a, 14)] << 8) | this.sb4[this.getByte(a, 15)];
    }
    ;
    sl2(b, a) {
        b[0] = (this.sb3[this.getByte(a, 0)] << 24) | (this.sb4[this.getByte(a, 1)] << 16) | (this.sb1[this.getByte(a, 2)] << 8) | this.sb2[this.getByte(a, 3)];
        b[1] = (this.sb3[this.getByte(a, 4)] << 24) | (this.sb4[this.getByte(a, 5)] << 16) | (this.sb1[this.getByte(a, 6)] << 8) | this.sb2[this.getByte(a, 7)];
        b[2] = (this.sb3[this.getByte(a, 8)] << 24) | (this.sb4[this.getByte(a, 9)] << 16) | (this.sb1[this.getByte(a, 10)] << 8) | this.sb2[this.getByte(a, 11)];
        b[3] = (this.sb3[this.getByte(a, 12)] << 24) | (this.sb4[this.getByte(a, 13)] << 16) | (this.sb1[this.getByte(a, 14)] << 8) | this.sb2[this.getByte(a, 15)];
    }
    ;
    a(b, a) {
        b[0] = ((this.getByte(a, 3) ^ this.getByte(a, 4) ^ this.getByte(a, 6) ^ this.getByte(a, 8) ^ this.getByte(a, 9) ^ this.getByte(a, 13) ^ this.getByte(a, 14)) << 24 |
            (this.getByte(a, 2) ^ this.getByte(a, 5) ^ this.getByte(a, 7) ^ this.getByte(a, 8) ^ this.getByte(a, 9) ^ this.getByte(a, 12) ^ this.getByte(a, 15)) << 16 |
            (this.getByte(a, 1) ^ this.getByte(a, 4) ^ this.getByte(a, 6) ^ this.getByte(a, 10) ^ this.getByte(a, 11) ^ this.getByte(a, 12) ^ this.getByte(a, 15)) << 8 |
            (this.getByte(a, 0) ^ this.getByte(a, 5) ^ this.getByte(a, 7) ^ this.getByte(a, 10) ^ this.getByte(a, 11) ^ this.getByte(a, 13) ^ this.getByte(a, 14))) >>> 0;
        b[1] = ((this.getByte(a, 0) ^ this.getByte(a, 2) ^ this.getByte(a, 5) ^ this.getByte(a, 8) ^ this.getByte(a, 11) ^ this.getByte(a, 14) ^ this.getByte(a, 15)) << 24 |
            (this.getByte(a, 1) ^ this.getByte(a, 3) ^ this.getByte(a, 4) ^ this.getByte(a, 9) ^ this.getByte(a, 10) ^ this.getByte(a, 14) ^ this.getByte(a, 15)) << 16 |
            (this.getByte(a, 0) ^ this.getByte(a, 2) ^ this.getByte(a, 7) ^ this.getByte(a, 9) ^ this.getByte(a, 10) ^ this.getByte(a, 12) ^ this.getByte(a, 13)) << 8 |
            (this.getByte(a, 1) ^ this.getByte(a, 3) ^ this.getByte(a, 6) ^ this.getByte(a, 8) ^ this.getByte(a, 11) ^ this.getByte(a, 12) ^ this.getByte(a, 13))) >>> 0;
        b[2] = ((this.getByte(a, 0) ^ this.getByte(a, 1) ^ this.getByte(a, 4) ^ this.getByte(a, 7) ^ this.getByte(a, 10) ^ this.getByte(a, 13) ^ this.getByte(a, 15)) << 24 |
            (this.getByte(a, 0) ^ this.getByte(a, 1) ^ this.getByte(a, 5) ^ this.getByte(a, 6) ^ this.getByte(a, 11) ^ this.getByte(a, 12) ^ this.getByte(a, 14)) << 16 |
            (this.getByte(a, 2) ^ this.getByte(a, 3) ^ this.getByte(a, 5) ^ this.getByte(a, 6) ^ this.getByte(a, 8) ^ this.getByte(a, 13) ^ this.getByte(a, 15)) << 8 |
            (this.getByte(a, 2) ^ this.getByte(a, 3) ^ this.getByte(a, 4) ^ this.getByte(a, 7) ^ this.getByte(a, 9) ^ this.getByte(a, 12) ^ this.getByte(a, 14))) >>> 0;
        b[3] = ((this.getByte(a, 1) ^ this.getByte(a, 2) ^ this.getByte(a, 6) ^ this.getByte(a, 7) ^ this.getByte(a, 9) ^ this.getByte(a, 11) ^ this.getByte(a, 12)) << 24 |
            (this.getByte(a, 0) ^ this.getByte(a, 3) ^ this.getByte(a, 6) ^ this.getByte(a, 7) ^ this.getByte(a, 8) ^ this.getByte(a, 10) ^ this.getByte(a, 13)) << 16 |
            (this.getByte(a, 0) ^ this.getByte(a, 3) ^ this.getByte(a, 4) ^ this.getByte(a, 5) ^ this.getByte(a, 9) ^ this.getByte(a, 11) ^ this.getByte(a, 14)) << 8 |
            (this.getByte(a, 1) ^ this.getByte(a, 2) ^ this.getByte(a, 4) ^ this.getByte(a, 5) ^ this.getByte(a, 8) ^ this.getByte(a, 10) ^ this.getByte(a, 15))) >>> 0;
    }
    ;
    // Odd round function
    of(d, rk) {
        const t = new Uint32Array(4);
        this.xor128(d, rk);
        this.sl1(t, d);
        this.a(d, t);
    }
    ;
    // Even round function
    ef(d, rk) {
        const t = new Uint32Array(4);
        this.xor128(d, rk);
        this.sl2(t, d);
        this.a(d, t);
    }
    ;
    // Initialize ARIA context
    set_key(key) {
        const keyLen = key.length;
        let ck1, ck2, ck3;
        if (keyLen === 16) {
            this.nr = 12;
            ck1 = this.c.subarray(0, 4);
            ck2 = this.c.subarray(4, 8);
            ck3 = this.c.subarray(8, 12);
        }
        else if (keyLen === 24) {
            this.nr = 14;
            ck1 = this.c.subarray(4, 8);
            ck2 = this.c.subarray(8, 12);
            ck3 = this.c.subarray(0, 4);
        }
        else if (keyLen === 32) {
            this.nr = 16;
            ck1 = this.c.subarray(8, 12);
            ck2 = this.c.subarray(0, 4);
            ck3 = this.c.subarray(4, 8);
        }
        else {
            throw new Error("INVALID_KEY_LENGTH");
        }
        const keyWords = keyLen / 4;
        const w = new Uint32Array(16);
        for (let i = 0; i < 16; i++) {
            if (i < keyWords) {
                w[i] = this.load32BE(key, i * 4);
            }
            else {
                w[i] = 0;
            }
        }
        // Save KR
        this.mov128(w.subarray(8, 12), w.subarray(4, 8));
        // Compute intermediate values W0, W1, W2, W3
        this.mov128(w.subarray(4, 8), w.subarray(0, 4));
        this.of(w.subarray(4, 8), ck1);
        this.xor128(w.subarray(4, 8), w.subarray(8, 12));
        this.mov128(w.subarray(8, 12), w.subarray(4, 8));
        this.ef(w.subarray(8, 12), ck2);
        this.xor128(w.subarray(8, 12), w.subarray(0, 4));
        this.mov128(w.subarray(12, 16), w.subarray(8, 12));
        this.of(w.subarray(12, 16), ck3);
        this.xor128(w.subarray(12, 16), w.subarray(4, 8));
        // Compute encryption round keys
        const ek = this.ek;
        this.rol128(ek.subarray(0, 4), w.subarray(4, 8), 109);
        this.xor128(ek.subarray(0, 4), w.subarray(0, 4));
        this.rol128(ek.subarray(4, 8), w.subarray(8, 12), 109);
        this.xor128(ek.subarray(4, 8), w.subarray(4, 8));
        this.rol128(ek.subarray(8, 12), w.subarray(12, 16), 109);
        this.xor128(ek.subarray(8, 12), w.subarray(8, 12));
        this.rol128(ek.subarray(12, 16), w.subarray(0, 4), 109);
        this.xor128(ek.subarray(12, 16), w.subarray(12, 16));
        this.rol128(ek.subarray(16, 20), w.subarray(4, 8), 97);
        this.xor128(ek.subarray(16, 20), w.subarray(0, 4));
        this.rol128(ek.subarray(20, 24), w.subarray(8, 12), 97);
        this.xor128(ek.subarray(20, 24), w.subarray(4, 8));
        this.rol128(ek.subarray(24, 28), w.subarray(12, 16), 97);
        this.xor128(ek.subarray(24, 28), w.subarray(8, 12));
        this.rol128(ek.subarray(28, 32), w.subarray(0, 4), 97);
        this.xor128(ek.subarray(28, 32), w.subarray(12, 16));
        this.rol128(ek.subarray(32, 36), w.subarray(4, 8), 61);
        this.xor128(ek.subarray(32, 36), w.subarray(0, 4));
        this.rol128(ek.subarray(36, 40), w.subarray(8, 12), 61);
        this.xor128(ek.subarray(36, 40), w.subarray(4, 8));
        this.rol128(ek.subarray(40, 44), w.subarray(12, 16), 61);
        this.xor128(ek.subarray(40, 44), w.subarray(8, 12));
        this.rol128(ek.subarray(44, 48), w.subarray(0, 4), 61);
        this.xor128(ek.subarray(44, 48), w.subarray(12, 16));
        this.rol128(ek.subarray(48, 52), w.subarray(4, 8), 31);
        this.xor128(ek.subarray(48, 52), w.subarray(0, 4));
        this.rol128(ek.subarray(52, 56), w.subarray(8, 12), 31);
        this.xor128(ek.subarray(52, 56), w.subarray(4, 8));
        this.rol128(ek.subarray(56, 60), w.subarray(12, 16), 31);
        this.xor128(ek.subarray(56, 60), w.subarray(8, 12));
        this.rol128(ek.subarray(60, 64), w.subarray(0, 4), 31);
        this.xor128(ek.subarray(60, 64), w.subarray(12, 16));
        this.rol128(ek.subarray(64, 68), w.subarray(4, 8), 19);
        this.xor128(ek.subarray(64, 68), w.subarray(0, 4));
        // Compute decryption round keys
        const dk = this.dk;
        this.mov128(dk.subarray(0, 4), ek.subarray(this.nr * 4, this.nr * 4 + 4));
        for (let i = 1; i < this.nr; i++) {
            this.a(dk.subarray(i * 4, i * 4 + 4), ek.subarray((this.nr - i) * 4, (this.nr - i) * 4 + 4));
        }
        this.mov128(dk.subarray(this.nr * 4, this.nr * 4 + 4), ek.subarray(0, 4));
        this.key_set = true;
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be same length as key!
     *
     * @param {Buffer} iv - ```Buffer```
     */
    set_iv(iv) {
        if (this.key_set != true) {
            throw new Error("Must set key before IV");
        }
        if (iv) {
            if (iv.length != 16) {
                throw new Error(`Enter a vaild 16 byte IV for CBC mode`);
            }
            else {
                this.iv = iv;
                this.iv_set = true;
            }
        }
        else {
            throw new Error(`Enter a vaild 16 byte IV for CBC mode`);
        }
    }
    ;
    // Encrypt a 16-byte block
    encrypt_block(input, last_block) {
        const p = new Uint32Array(4);
        const q = new Uint32Array(4);
        const output = Buffer.alloc(16);
        const ek = this.ek;
        if (last_block) {
            input = padd_block(input);
        }
        if (this.iv_set == true && this.iv) {
            input = xor(input, this.iv);
        }
        p[0] = this.load32BE(input, 0);
        p[1] = this.load32BE(input, 4);
        p[2] = this.load32BE(input, 8);
        p[3] = this.load32BE(input, 12);
        this.of(p, ek.subarray(0, 4));
        this.ef(p, ek.subarray(4, 8));
        this.of(p, ek.subarray(8, 12));
        this.ef(p, ek.subarray(12, 16));
        this.of(p, ek.subarray(16, 20));
        this.ef(p, ek.subarray(20, 24));
        this.of(p, ek.subarray(24, 28));
        this.ef(p, ek.subarray(28, 32));
        this.of(p, ek.subarray(32, 36));
        this.ef(p, ek.subarray(36, 40));
        this.of(p, ek.subarray(40, 44));
        if (this.nr === 12) {
            this.xor128(p, ek.subarray(44, 48));
            this.sl2(q, p);
            this.xor128(q, ek.subarray(48, 52));
        }
        else if (this.nr === 14) {
            this.ef(p, ek.subarray(44, 48));
            this.of(p, ek.subarray(48, 52));
            this.xor128(p, ek.subarray(52, 56));
            this.sl2(q, p);
            this.xor128(q, ek.subarray(56, 60));
        }
        else {
            this.ef(p, ek.subarray(44, 48));
            this.of(p, ek.subarray(48, 52));
            this.ef(p, ek.subarray(52, 56));
            this.of(p, ek.subarray(56, 60));
            this.xor128(p, ek.subarray(60, 64));
            this.sl2(q, p);
            this.xor128(q, ek.subarray(64, 68));
        }
        this.store32BE(q[0], output, 0);
        this.store32BE(q[1], output, 4);
        this.store32BE(q[2], output, 8);
        this.store32BE(q[3], output, 12);
        if (this.iv_set == true) {
            this.iv = output;
        }
        return output;
    }
    ;
    // Decrypt a 16-byte block
    decrypt_block(input, last_block) {
        const p = new Uint32Array(4);
        const q = new Uint32Array(4);
        const output = Buffer.alloc(16);
        const dk = this.dk;
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = input;
        p[0] = this.load32BE(input, 0);
        p[1] = this.load32BE(input, 4);
        p[2] = this.load32BE(input, 8);
        p[3] = this.load32BE(input, 12);
        this.of(p, dk.subarray(0, 4));
        this.ef(p, dk.subarray(4, 8));
        this.of(p, dk.subarray(8, 12));
        this.ef(p, dk.subarray(12, 16));
        this.of(p, dk.subarray(16, 20));
        this.ef(p, dk.subarray(20, 24));
        this.of(p, dk.subarray(24, 28));
        this.ef(p, dk.subarray(28, 32));
        this.of(p, dk.subarray(32, 36));
        this.ef(p, dk.subarray(36, 40));
        this.of(p, dk.subarray(40, 44));
        if (this.nr === 12) {
            this.xor128(p, dk.subarray(44, 48));
            this.sl2(q, p);
            this.xor128(q, dk.subarray(48, 52));
        }
        else if (this.nr === 14) {
            this.ef(p, dk.subarray(44, 48));
            this.of(p, dk.subarray(48, 52));
            this.xor128(p, dk.subarray(52, 56));
            this.sl2(q, p);
            this.xor128(q, dk.subarray(56, 60));
        }
        else {
            this.ef(p, dk.subarray(44, 48));
            this.of(p, dk.subarray(48, 52));
            this.ef(p, dk.subarray(52, 56));
            this.of(p, dk.subarray(56, 60));
            this.xor128(p, dk.subarray(60, 64));
            this.sl2(q, p);
            this.xor128(q, dk.subarray(64, 68));
        }
        this.store32BE(q[0], output, 0);
        this.store32BE(q[1], output, 4);
        this.store32BE(q[2], output, 8);
        this.store32BE(q[3], output, 12);
        if (this.iv_set == true && this.iv) {
            xor(output, this.iv);
        }
        if (last_block) {
            var padd_value = align(output.length, 16);
            return removePKCSPadding(output, padd_value, true);
        }
        return output;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer```
     */
    encrypt(data_in, padding = 0) {
        const block_size = this.ARIA_BLOCK_SIZE;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0; index < data.length / block_size; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            const return_block = this.encrypt_block(block);
            return_buff.push(return_block);
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns ```Buffer```
     */
    decrypt(data_in, remove_padding = true) {
        const block_size = 16;
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            const block = data.subarray((index * block_size), (index + 1) * block_size);
            var return_block = this.decrypt_block(block);
            if ((remove_padding != false) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
}
class CAMELLIA {
    constructor() {
        this.key_set = false;
        this.iv_set = false;
        this.MASK8 = 0xFF;
        this.initialized = false;
        this._keyis128 = false;
        this.subkey = new Uint32Array(96);
        this.kw = new Uint32Array(8);
        this.ke = new Uint32Array(12);
        this.state = new Uint32Array(4);
        this.SIGMA = new Uint32Array([
            0xa09e667f, 0x3bcc908b,
            0xb67ae858, 0x4caa73b2,
            0xc6ef372f, 0xe94f82be,
            0x54ff53a5, 0xf1d36f1c,
            0x10e527fa, 0xde682d1d,
            0xb05688c2, 0xb3e6c1fd
        ]);
        this.SBOX1_1110 = new Uint32Array([
            0x70707000, 0x82828200, 0x2c2c2c00, 0xececec00, 0xb3b3b300, 0x27272700,
            0xc0c0c000, 0xe5e5e500, 0xe4e4e400, 0x85858500, 0x57575700, 0x35353500,
            0xeaeaea00, 0x0c0c0c00, 0xaeaeae00, 0x41414100, 0x23232300, 0xefefef00,
            0x6b6b6b00, 0x93939300, 0x45454500, 0x19191900, 0xa5a5a500, 0x21212100,
            0xededed00, 0x0e0e0e00, 0x4f4f4f00, 0x4e4e4e00, 0x1d1d1d00, 0x65656500,
            0x92929200, 0xbdbdbd00, 0x86868600, 0xb8b8b800, 0xafafaf00, 0x8f8f8f00,
            0x7c7c7c00, 0xebebeb00, 0x1f1f1f00, 0xcecece00, 0x3e3e3e00, 0x30303000,
            0xdcdcdc00, 0x5f5f5f00, 0x5e5e5e00, 0xc5c5c500, 0x0b0b0b00, 0x1a1a1a00,
            0xa6a6a600, 0xe1e1e100, 0x39393900, 0xcacaca00, 0xd5d5d500, 0x47474700,
            0x5d5d5d00, 0x3d3d3d00, 0xd9d9d900, 0x01010100, 0x5a5a5a00, 0xd6d6d600,
            0x51515100, 0x56565600, 0x6c6c6c00, 0x4d4d4d00, 0x8b8b8b00, 0x0d0d0d00,
            0x9a9a9a00, 0x66666600, 0xfbfbfb00, 0xcccccc00, 0xb0b0b000, 0x2d2d2d00,
            0x74747400, 0x12121200, 0x2b2b2b00, 0x20202000, 0xf0f0f000, 0xb1b1b100,
            0x84848400, 0x99999900, 0xdfdfdf00, 0x4c4c4c00, 0xcbcbcb00, 0xc2c2c200,
            0x34343400, 0x7e7e7e00, 0x76767600, 0x05050500, 0x6d6d6d00, 0xb7b7b700,
            0xa9a9a900, 0x31313100, 0xd1d1d100, 0x17171700, 0x04040400, 0xd7d7d700,
            0x14141400, 0x58585800, 0x3a3a3a00, 0x61616100, 0xdedede00, 0x1b1b1b00,
            0x11111100, 0x1c1c1c00, 0x32323200, 0x0f0f0f00, 0x9c9c9c00, 0x16161600,
            0x53535300, 0x18181800, 0xf2f2f200, 0x22222200, 0xfefefe00, 0x44444400,
            0xcfcfcf00, 0xb2b2b200, 0xc3c3c300, 0xb5b5b500, 0x7a7a7a00, 0x91919100,
            0x24242400, 0x08080800, 0xe8e8e800, 0xa8a8a800, 0x60606000, 0xfcfcfc00,
            0x69696900, 0x50505000, 0xaaaaaa00, 0xd0d0d000, 0xa0a0a000, 0x7d7d7d00,
            0xa1a1a100, 0x89898900, 0x62626200, 0x97979700, 0x54545400, 0x5b5b5b00,
            0x1e1e1e00, 0x95959500, 0xe0e0e000, 0xffffff00, 0x64646400, 0xd2d2d200,
            0x10101000, 0xc4c4c400, 0x00000000, 0x48484800, 0xa3a3a300, 0xf7f7f700,
            0x75757500, 0xdbdbdb00, 0x8a8a8a00, 0x03030300, 0xe6e6e600, 0xdadada00,
            0x09090900, 0x3f3f3f00, 0xdddddd00, 0x94949400, 0x87878700, 0x5c5c5c00,
            0x83838300, 0x02020200, 0xcdcdcd00, 0x4a4a4a00, 0x90909000, 0x33333300,
            0x73737300, 0x67676700, 0xf6f6f600, 0xf3f3f300, 0x9d9d9d00, 0x7f7f7f00,
            0xbfbfbf00, 0xe2e2e200, 0x52525200, 0x9b9b9b00, 0xd8d8d800, 0x26262600,
            0xc8c8c800, 0x37373700, 0xc6c6c600, 0x3b3b3b00, 0x81818100, 0x96969600,
            0x6f6f6f00, 0x4b4b4b00, 0x13131300, 0xbebebe00, 0x63636300, 0x2e2e2e00,
            0xe9e9e900, 0x79797900, 0xa7a7a700, 0x8c8c8c00, 0x9f9f9f00, 0x6e6e6e00,
            0xbcbcbc00, 0x8e8e8e00, 0x29292900, 0xf5f5f500, 0xf9f9f900, 0xb6b6b600,
            0x2f2f2f00, 0xfdfdfd00, 0xb4b4b400, 0x59595900, 0x78787800, 0x98989800,
            0x06060600, 0x6a6a6a00, 0xe7e7e700, 0x46464600, 0x71717100, 0xbababa00,
            0xd4d4d400, 0x25252500, 0xababab00, 0x42424200, 0x88888800, 0xa2a2a200,
            0x8d8d8d00, 0xfafafa00, 0x72727200, 0x07070700, 0xb9b9b900, 0x55555500,
            0xf8f8f800, 0xeeeeee00, 0xacacac00, 0x0a0a0a00, 0x36363600, 0x49494900,
            0x2a2a2a00, 0x68686800, 0x3c3c3c00, 0x38383800, 0xf1f1f100, 0xa4a4a400,
            0x40404000, 0x28282800, 0xd3d3d300, 0x7b7b7b00, 0xbbbbbb00, 0xc9c9c900,
            0x43434300, 0xc1c1c100, 0x15151500, 0xe3e3e300, 0xadadad00, 0xf4f4f400,
            0x77777700, 0xc7c7c700, 0x80808000, 0x9e9e9e00
        ]);
        this.SBOX4_4404 = new Uint32Array([
            0x70700070, 0x2c2c002c, 0xb3b300b3, 0xc0c000c0, 0xe4e400e4, 0x57570057,
            0xeaea00ea, 0xaeae00ae, 0x23230023, 0x6b6b006b, 0x45450045, 0xa5a500a5,
            0xeded00ed, 0x4f4f004f, 0x1d1d001d, 0x92920092, 0x86860086, 0xafaf00af,
            0x7c7c007c, 0x1f1f001f, 0x3e3e003e, 0xdcdc00dc, 0x5e5e005e, 0x0b0b000b,
            0xa6a600a6, 0x39390039, 0xd5d500d5, 0x5d5d005d, 0xd9d900d9, 0x5a5a005a,
            0x51510051, 0x6c6c006c, 0x8b8b008b, 0x9a9a009a, 0xfbfb00fb, 0xb0b000b0,
            0x74740074, 0x2b2b002b, 0xf0f000f0, 0x84840084, 0xdfdf00df, 0xcbcb00cb,
            0x34340034, 0x76760076, 0x6d6d006d, 0xa9a900a9, 0xd1d100d1, 0x04040004,
            0x14140014, 0x3a3a003a, 0xdede00de, 0x11110011, 0x32320032, 0x9c9c009c,
            0x53530053, 0xf2f200f2, 0xfefe00fe, 0xcfcf00cf, 0xc3c300c3, 0x7a7a007a,
            0x24240024, 0xe8e800e8, 0x60600060, 0x69690069, 0xaaaa00aa, 0xa0a000a0,
            0xa1a100a1, 0x62620062, 0x54540054, 0x1e1e001e, 0xe0e000e0, 0x64640064,
            0x10100010, 0x00000000, 0xa3a300a3, 0x75750075, 0x8a8a008a, 0xe6e600e6,
            0x09090009, 0xdddd00dd, 0x87870087, 0x83830083, 0xcdcd00cd, 0x90900090,
            0x73730073, 0xf6f600f6, 0x9d9d009d, 0xbfbf00bf, 0x52520052, 0xd8d800d8,
            0xc8c800c8, 0xc6c600c6, 0x81810081, 0x6f6f006f, 0x13130013, 0x63630063,
            0xe9e900e9, 0xa7a700a7, 0x9f9f009f, 0xbcbc00bc, 0x29290029, 0xf9f900f9,
            0x2f2f002f, 0xb4b400b4, 0x78780078, 0x06060006, 0xe7e700e7, 0x71710071,
            0xd4d400d4, 0xabab00ab, 0x88880088, 0x8d8d008d, 0x72720072, 0xb9b900b9,
            0xf8f800f8, 0xacac00ac, 0x36360036, 0x2a2a002a, 0x3c3c003c, 0xf1f100f1,
            0x40400040, 0xd3d300d3, 0xbbbb00bb, 0x43430043, 0x15150015, 0xadad00ad,
            0x77770077, 0x80800080, 0x82820082, 0xecec00ec, 0x27270027, 0xe5e500e5,
            0x85850085, 0x35350035, 0x0c0c000c, 0x41410041, 0xefef00ef, 0x93930093,
            0x19190019, 0x21210021, 0x0e0e000e, 0x4e4e004e, 0x65650065, 0xbdbd00bd,
            0xb8b800b8, 0x8f8f008f, 0xebeb00eb, 0xcece00ce, 0x30300030, 0x5f5f005f,
            0xc5c500c5, 0x1a1a001a, 0xe1e100e1, 0xcaca00ca, 0x47470047, 0x3d3d003d,
            0x01010001, 0xd6d600d6, 0x56560056, 0x4d4d004d, 0x0d0d000d, 0x66660066,
            0xcccc00cc, 0x2d2d002d, 0x12120012, 0x20200020, 0xb1b100b1, 0x99990099,
            0x4c4c004c, 0xc2c200c2, 0x7e7e007e, 0x05050005, 0xb7b700b7, 0x31310031,
            0x17170017, 0xd7d700d7, 0x58580058, 0x61610061, 0x1b1b001b, 0x1c1c001c,
            0x0f0f000f, 0x16160016, 0x18180018, 0x22220022, 0x44440044, 0xb2b200b2,
            0xb5b500b5, 0x91910091, 0x08080008, 0xa8a800a8, 0xfcfc00fc, 0x50500050,
            0xd0d000d0, 0x7d7d007d, 0x89890089, 0x97970097, 0x5b5b005b, 0x95950095,
            0xffff00ff, 0xd2d200d2, 0xc4c400c4, 0x48480048, 0xf7f700f7, 0xdbdb00db,
            0x03030003, 0xdada00da, 0x3f3f003f, 0x94940094, 0x5c5c005c, 0x02020002,
            0x4a4a004a, 0x33330033, 0x67670067, 0xf3f300f3, 0x7f7f007f, 0xe2e200e2,
            0x9b9b009b, 0x26260026, 0x37370037, 0x3b3b003b, 0x96960096, 0x4b4b004b,
            0xbebe00be, 0x2e2e002e, 0x79790079, 0x8c8c008c, 0x6e6e006e, 0x8e8e008e,
            0xf5f500f5, 0xb6b600b6, 0xfdfd00fd, 0x59590059, 0x98980098, 0x6a6a006a,
            0x46460046, 0xbaba00ba, 0x25250025, 0x42420042, 0xa2a200a2, 0xfafa00fa,
            0x07070007, 0x55550055, 0xeeee00ee, 0x0a0a000a, 0x49490049, 0x68680068,
            0x38380038, 0xa4a400a4, 0x28280028, 0x7b7b007b, 0xc9c900c9, 0xc1c100c1,
            0xe3e300e3, 0xf4f400f4, 0xc7c700c7, 0x9e9e009e
        ]);
        this.SBOX2_0222 = new Uint32Array([
            0x00e0e0e0, 0x00050505, 0x00585858, 0x00d9d9d9, 0x00676767, 0x004e4e4e,
            0x00818181, 0x00cbcbcb, 0x00c9c9c9, 0x000b0b0b, 0x00aeaeae, 0x006a6a6a,
            0x00d5d5d5, 0x00181818, 0x005d5d5d, 0x00828282, 0x00464646, 0x00dfdfdf,
            0x00d6d6d6, 0x00272727, 0x008a8a8a, 0x00323232, 0x004b4b4b, 0x00424242,
            0x00dbdbdb, 0x001c1c1c, 0x009e9e9e, 0x009c9c9c, 0x003a3a3a, 0x00cacaca,
            0x00252525, 0x007b7b7b, 0x000d0d0d, 0x00717171, 0x005f5f5f, 0x001f1f1f,
            0x00f8f8f8, 0x00d7d7d7, 0x003e3e3e, 0x009d9d9d, 0x007c7c7c, 0x00606060,
            0x00b9b9b9, 0x00bebebe, 0x00bcbcbc, 0x008b8b8b, 0x00161616, 0x00343434,
            0x004d4d4d, 0x00c3c3c3, 0x00727272, 0x00959595, 0x00ababab, 0x008e8e8e,
            0x00bababa, 0x007a7a7a, 0x00b3b3b3, 0x00020202, 0x00b4b4b4, 0x00adadad,
            0x00a2a2a2, 0x00acacac, 0x00d8d8d8, 0x009a9a9a, 0x00171717, 0x001a1a1a,
            0x00353535, 0x00cccccc, 0x00f7f7f7, 0x00999999, 0x00616161, 0x005a5a5a,
            0x00e8e8e8, 0x00242424, 0x00565656, 0x00404040, 0x00e1e1e1, 0x00636363,
            0x00090909, 0x00333333, 0x00bfbfbf, 0x00989898, 0x00979797, 0x00858585,
            0x00686868, 0x00fcfcfc, 0x00ececec, 0x000a0a0a, 0x00dadada, 0x006f6f6f,
            0x00535353, 0x00626262, 0x00a3a3a3, 0x002e2e2e, 0x00080808, 0x00afafaf,
            0x00282828, 0x00b0b0b0, 0x00747474, 0x00c2c2c2, 0x00bdbdbd, 0x00363636,
            0x00222222, 0x00383838, 0x00646464, 0x001e1e1e, 0x00393939, 0x002c2c2c,
            0x00a6a6a6, 0x00303030, 0x00e5e5e5, 0x00444444, 0x00fdfdfd, 0x00888888,
            0x009f9f9f, 0x00656565, 0x00878787, 0x006b6b6b, 0x00f4f4f4, 0x00232323,
            0x00484848, 0x00101010, 0x00d1d1d1, 0x00515151, 0x00c0c0c0, 0x00f9f9f9,
            0x00d2d2d2, 0x00a0a0a0, 0x00555555, 0x00a1a1a1, 0x00414141, 0x00fafafa,
            0x00434343, 0x00131313, 0x00c4c4c4, 0x002f2f2f, 0x00a8a8a8, 0x00b6b6b6,
            0x003c3c3c, 0x002b2b2b, 0x00c1c1c1, 0x00ffffff, 0x00c8c8c8, 0x00a5a5a5,
            0x00202020, 0x00898989, 0x00000000, 0x00909090, 0x00474747, 0x00efefef,
            0x00eaeaea, 0x00b7b7b7, 0x00151515, 0x00060606, 0x00cdcdcd, 0x00b5b5b5,
            0x00121212, 0x007e7e7e, 0x00bbbbbb, 0x00292929, 0x000f0f0f, 0x00b8b8b8,
            0x00070707, 0x00040404, 0x009b9b9b, 0x00949494, 0x00212121, 0x00666666,
            0x00e6e6e6, 0x00cecece, 0x00ededed, 0x00e7e7e7, 0x003b3b3b, 0x00fefefe,
            0x007f7f7f, 0x00c5c5c5, 0x00a4a4a4, 0x00373737, 0x00b1b1b1, 0x004c4c4c,
            0x00919191, 0x006e6e6e, 0x008d8d8d, 0x00767676, 0x00030303, 0x002d2d2d,
            0x00dedede, 0x00969696, 0x00262626, 0x007d7d7d, 0x00c6c6c6, 0x005c5c5c,
            0x00d3d3d3, 0x00f2f2f2, 0x004f4f4f, 0x00191919, 0x003f3f3f, 0x00dcdcdc,
            0x00797979, 0x001d1d1d, 0x00525252, 0x00ebebeb, 0x00f3f3f3, 0x006d6d6d,
            0x005e5e5e, 0x00fbfbfb, 0x00696969, 0x00b2b2b2, 0x00f0f0f0, 0x00313131,
            0x000c0c0c, 0x00d4d4d4, 0x00cfcfcf, 0x008c8c8c, 0x00e2e2e2, 0x00757575,
            0x00a9a9a9, 0x004a4a4a, 0x00575757, 0x00848484, 0x00111111, 0x00454545,
            0x001b1b1b, 0x00f5f5f5, 0x00e4e4e4, 0x000e0e0e, 0x00737373, 0x00aaaaaa,
            0x00f1f1f1, 0x00dddddd, 0x00595959, 0x00141414, 0x006c6c6c, 0x00929292,
            0x00545454, 0x00d0d0d0, 0x00787878, 0x00707070, 0x00e3e3e3, 0x00494949,
            0x00808080, 0x00505050, 0x00a7a7a7, 0x00f6f6f6, 0x00777777, 0x00939393,
            0x00868686, 0x00838383, 0x002a2a2a, 0x00c7c7c7, 0x005b5b5b, 0x00e9e9e9,
            0x00eeeeee, 0x008f8f8f, 0x00010101, 0x003d3d3d
        ]);
        this.SBOX3_3033 = new Uint32Array([
            0x38003838, 0x41004141, 0x16001616, 0x76007676, 0xd900d9d9, 0x93009393,
            0x60006060, 0xf200f2f2, 0x72007272, 0xc200c2c2, 0xab00abab, 0x9a009a9a,
            0x75007575, 0x06000606, 0x57005757, 0xa000a0a0, 0x91009191, 0xf700f7f7,
            0xb500b5b5, 0xc900c9c9, 0xa200a2a2, 0x8c008c8c, 0xd200d2d2, 0x90009090,
            0xf600f6f6, 0x07000707, 0xa700a7a7, 0x27002727, 0x8e008e8e, 0xb200b2b2,
            0x49004949, 0xde00dede, 0x43004343, 0x5c005c5c, 0xd700d7d7, 0xc700c7c7,
            0x3e003e3e, 0xf500f5f5, 0x8f008f8f, 0x67006767, 0x1f001f1f, 0x18001818,
            0x6e006e6e, 0xaf00afaf, 0x2f002f2f, 0xe200e2e2, 0x85008585, 0x0d000d0d,
            0x53005353, 0xf000f0f0, 0x9c009c9c, 0x65006565, 0xea00eaea, 0xa300a3a3,
            0xae00aeae, 0x9e009e9e, 0xec00ecec, 0x80008080, 0x2d002d2d, 0x6b006b6b,
            0xa800a8a8, 0x2b002b2b, 0x36003636, 0xa600a6a6, 0xc500c5c5, 0x86008686,
            0x4d004d4d, 0x33003333, 0xfd00fdfd, 0x66006666, 0x58005858, 0x96009696,
            0x3a003a3a, 0x09000909, 0x95009595, 0x10001010, 0x78007878, 0xd800d8d8,
            0x42004242, 0xcc00cccc, 0xef00efef, 0x26002626, 0xe500e5e5, 0x61006161,
            0x1a001a1a, 0x3f003f3f, 0x3b003b3b, 0x82008282, 0xb600b6b6, 0xdb00dbdb,
            0xd400d4d4, 0x98009898, 0xe800e8e8, 0x8b008b8b, 0x02000202, 0xeb00ebeb,
            0x0a000a0a, 0x2c002c2c, 0x1d001d1d, 0xb000b0b0, 0x6f006f6f, 0x8d008d8d,
            0x88008888, 0x0e000e0e, 0x19001919, 0x87008787, 0x4e004e4e, 0x0b000b0b,
            0xa900a9a9, 0x0c000c0c, 0x79007979, 0x11001111, 0x7f007f7f, 0x22002222,
            0xe700e7e7, 0x59005959, 0xe100e1e1, 0xda00dada, 0x3d003d3d, 0xc800c8c8,
            0x12001212, 0x04000404, 0x74007474, 0x54005454, 0x30003030, 0x7e007e7e,
            0xb400b4b4, 0x28002828, 0x55005555, 0x68006868, 0x50005050, 0xbe00bebe,
            0xd000d0d0, 0xc400c4c4, 0x31003131, 0xcb00cbcb, 0x2a002a2a, 0xad00adad,
            0x0f000f0f, 0xca00caca, 0x70007070, 0xff00ffff, 0x32003232, 0x69006969,
            0x08000808, 0x62006262, 0x00000000, 0x24002424, 0xd100d1d1, 0xfb00fbfb,
            0xba00baba, 0xed00eded, 0x45004545, 0x81008181, 0x73007373, 0x6d006d6d,
            0x84008484, 0x9f009f9f, 0xee00eeee, 0x4a004a4a, 0xc300c3c3, 0x2e002e2e,
            0xc100c1c1, 0x01000101, 0xe600e6e6, 0x25002525, 0x48004848, 0x99009999,
            0xb900b9b9, 0xb300b3b3, 0x7b007b7b, 0xf900f9f9, 0xce00cece, 0xbf00bfbf,
            0xdf00dfdf, 0x71007171, 0x29002929, 0xcd00cdcd, 0x6c006c6c, 0x13001313,
            0x64006464, 0x9b009b9b, 0x63006363, 0x9d009d9d, 0xc000c0c0, 0x4b004b4b,
            0xb700b7b7, 0xa500a5a5, 0x89008989, 0x5f005f5f, 0xb100b1b1, 0x17001717,
            0xf400f4f4, 0xbc00bcbc, 0xd300d3d3, 0x46004646, 0xcf00cfcf, 0x37003737,
            0x5e005e5e, 0x47004747, 0x94009494, 0xfa00fafa, 0xfc00fcfc, 0x5b005b5b,
            0x97009797, 0xfe00fefe, 0x5a005a5a, 0xac00acac, 0x3c003c3c, 0x4c004c4c,
            0x03000303, 0x35003535, 0xf300f3f3, 0x23002323, 0xb800b8b8, 0x5d005d5d,
            0x6a006a6a, 0x92009292, 0xd500d5d5, 0x21002121, 0x44004444, 0x51005151,
            0xc600c6c6, 0x7d007d7d, 0x39003939, 0x83008383, 0xdc00dcdc, 0xaa00aaaa,
            0x7c007c7c, 0x77007777, 0x56005656, 0x05000505, 0x1b001b1b, 0xa400a4a4,
            0x15001515, 0x34003434, 0x1e001e1e, 0x1c001c1c, 0xf800f8f8, 0x52005252,
            0x20002020, 0x14001414, 0xe900e9e9, 0xbd00bdbd, 0xdd00dddd, 0xe400e4e4,
            0xa100a1a1, 0xe000e0e0, 0x8a008a8a, 0xf100f1f1, 0xd600d6d6, 0x7a007a7a,
            0xbb00bbbb, 0xe300e3e3, 0x40004040, 0x4f004f4f
        ]);
    }
    rightRotate(x, s) {
        return (((x) >>> (s)) + ((x) << (32 - s)));
    }
    leftRotate(x, s) {
        return (((x) << (s)) + ((x) >>> (32 - s)));
    }
    roldq(rot, ki, ioff, ko, ooff) {
        ko[0 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[2 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }
    decroldq(rot, ki, ioff, ko, ooff) {
        ko[2 + ooff] = (ki[0 + ioff] << rot) | (ki[1 + ioff] >>> (32 - rot));
        ko[3 + ooff] = (ki[1 + ioff] << rot) | (ki[2 + ioff] >>> (32 - rot));
        ko[0 + ooff] = (ki[2 + ioff] << rot) | (ki[3 + ioff] >>> (32 - rot));
        ko[1 + ooff] = (ki[3 + ioff] << rot) | (ki[0 + ioff] >>> (32 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }
    roldqo32(rot, ki, ioff, ko, ooff) {
        ko[0 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[2 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[0 + ooff];
        ki[1 + ioff] = ko[1 + ooff];
        ki[2 + ioff] = ko[2 + ooff];
        ki[3 + ioff] = ko[3 + ooff];
    }
    decroldqo32(rot, ki, ioff, ko, ooff) {
        ko[2 + ooff] = (ki[1 + ioff] << (rot - 32)) | (ki[2 + ioff] >>> (64 - rot));
        ko[3 + ooff] = (ki[2 + ioff] << (rot - 32)) | (ki[3 + ioff] >>> (64 - rot));
        ko[0 + ooff] = (ki[3 + ioff] << (rot - 32)) | (ki[0 + ioff] >>> (64 - rot));
        ko[1 + ooff] = (ki[0 + ioff] << (rot - 32)) | (ki[1 + ioff] >>> (64 - rot));
        ki[0 + ioff] = ko[2 + ooff];
        ki[1 + ioff] = ko[3 + ooff];
        ki[2 + ioff] = ko[0 + ooff];
        ki[3 + ioff] = ko[1 + ooff];
    }
    bytes2int(src, offset) {
        var word = new Uint32Array(1);
        for (var i = 0; i < 4; i++) {
            {
                word[0] = (word[0] << 8) + (src[i + offset] & this.MASK8);
            }
        }
        return word[0];
    }
    int2bytes(word, dst, offset) {
        for (var i = 0; i < 4; i++) {
            {
                dst[(3 - i) + offset] = (word | 0);
                word >>>= 8;
            }
        }
    }
    camelliaF2(s, skey, keyoff) {
        var t1;
        var t2;
        var u;
        var v;
        t1 = s[0] ^ skey[0 + keyoff];
        u = this.SBOX4_4404[t1 & this.MASK8];
        u ^= this.SBOX3_3033[(t1 >>> 8) & this.MASK8];
        u ^= this.SBOX2_0222[(t1 >>> 16) & this.MASK8];
        u ^= this.SBOX1_1110[(t1 >>> 24) & this.MASK8];
        t2 = s[1] ^ skey[1 + keyoff];
        v = this.SBOX1_1110[t2 & this.MASK8];
        v ^= this.SBOX4_4404[(t2 >>> 8) & this.MASK8];
        v ^= this.SBOX3_3033[(t2 >>> 16) & this.MASK8];
        v ^= this.SBOX2_0222[(t2 >>> 24) & this.MASK8];
        s[2] ^= u ^ v;
        s[3] ^= u ^ v ^ this.rightRotate(u, 8);
        t1 = s[2] ^ skey[2 + keyoff];
        u = this.SBOX4_4404[t1 & this.MASK8];
        u ^= this.SBOX3_3033[(t1 >>> 8) & this.MASK8];
        u ^= this.SBOX2_0222[(t1 >>> 16) & this.MASK8];
        u ^= this.SBOX1_1110[(t1 >>> 24) & this.MASK8];
        t2 = s[3] ^ skey[3 + keyoff];
        v = this.SBOX1_1110[t2 & this.MASK8];
        v ^= this.SBOX4_4404[(t2 >>> 8) & this.MASK8];
        v ^= this.SBOX3_3033[(t2 >>> 16) & this.MASK8];
        v ^= this.SBOX2_0222[(t2 >>> 24) & this.MASK8];
        s[0] ^= u ^ v;
        s[1] ^= u ^ v ^ this.rightRotate(u, 8);
    }
    camelliaFLs(s, fkey, keyoff) {
        s[1] ^= this.leftRotate(s[0] & fkey[0 + keyoff], 1);
        s[0] ^= fkey[1 + keyoff] | s[1];
        s[2] ^= fkey[3 + keyoff] | s[3];
        s[3] ^= this.leftRotate(fkey[2 + keyoff] & s[2], 1);
    }
    setkey(forEncryption, key) {
        var k = new Uint32Array(8);
        var ka = new Uint32Array(4);
        var kb = new Uint32Array(4);
        var t = new Uint32Array(4);
        switch ((key.length)) {
            case 16:
                this._keyis128 = true;
                k[0] = this.bytes2int(key, 0);
                k[1] = this.bytes2int(key, 4);
                k[2] = this.bytes2int(key, 8);
                k[3] = this.bytes2int(key, 12);
                k[4] = k[5] = k[6] = k[7] = 0;
                break;
            case 24:
                k[0] = this.bytes2int(key, 0);
                k[1] = this.bytes2int(key, 4);
                k[2] = this.bytes2int(key, 8);
                k[3] = this.bytes2int(key, 12);
                k[4] = this.bytes2int(key, 16);
                k[5] = this.bytes2int(key, 20);
                k[6] = ~k[4];
                k[7] = ~k[5];
                this._keyis128 = false;
                break;
            case 32:
                k[0] = this.bytes2int(key, 0);
                k[1] = this.bytes2int(key, 4);
                k[2] = this.bytes2int(key, 8);
                k[3] = this.bytes2int(key, 12);
                k[4] = this.bytes2int(key, 16);
                k[5] = this.bytes2int(key, 20);
                k[6] = this.bytes2int(key, 24);
                k[7] = this.bytes2int(key, 28);
                this._keyis128 = false;
                break;
            default:
                throw Error("key sizes are only 16/24/32 bytes.");
        }
        for (var i = 0; i < 4; i++) {
            {
                ka[i] = k[i] ^ k[i + 4];
            }
        }
        this.camelliaF2(ka, this.SIGMA, 0);
        for (var i = 0; i < 4; i++) {
            {
                ka[i] ^= k[i];
            }
        }
        this.camelliaF2(ka, this.SIGMA, 4);
        if (this._keyis128) {
            if (forEncryption) {
                this.kw[0] = k[0];
                this.kw[1] = k[1];
                this.kw[2] = k[2];
                this.kw[3] = k[3];
                this.roldq(15, k, 0, this.subkey, 4);
                this.roldq(30, k, 0, this.subkey, 12);
                this.roldq(15, k, 0, t, 0);
                this.subkey[18] = t[2];
                this.subkey[19] = t[3];
                this.roldq(17, k, 0, this.ke, 4);
                this.roldq(17, k, 0, this.subkey, 24);
                this.roldq(17, k, 0, this.subkey, 32);
                this.subkey[0] = ka[0];
                this.subkey[1] = ka[1];
                this.subkey[2] = ka[2];
                this.subkey[3] = ka[3];
                this.roldq(15, ka, 0, this.subkey, 8);
                this.roldq(15, ka, 0, this.ke, 0);
                this.roldq(15, ka, 0, t, 0);
                this.subkey[16] = t[0];
                this.subkey[17] = t[1];
                this.roldq(15, ka, 0, this.subkey, 20);
                this.roldqo32(34, ka, 0, this.subkey, 28);
                this.roldq(17, ka, 0, this.kw, 4);
            }
            else {
                this.kw[4] = k[0];
                this.kw[5] = k[1];
                this.kw[6] = k[2];
                this.kw[7] = k[3];
                this.decroldq(15, k, 0, this.subkey, 28);
                this.decroldq(30, k, 0, this.subkey, 20);
                this.decroldq(15, k, 0, t, 0);
                this.subkey[16] = t[0];
                this.subkey[17] = t[1];
                this.decroldq(17, k, 0, this.ke, 0);
                this.decroldq(17, k, 0, this.subkey, 8);
                this.decroldq(17, k, 0, this.subkey, 0);
                this.subkey[34] = ka[0];
                this.subkey[35] = ka[1];
                this.subkey[32] = ka[2];
                this.subkey[33] = ka[3];
                this.decroldq(15, ka, 0, this.subkey, 24);
                this.decroldq(15, ka, 0, this.ke, 4);
                this.decroldq(15, ka, 0, t, 0);
                this.subkey[18] = t[2];
                this.subkey[19] = t[3];
                this.decroldq(15, ka, 0, this.subkey, 12);
                this.decroldqo32(34, ka, 0, this.subkey, 4);
                this.roldq(17, ka, 0, this.kw, 0);
            }
        }
        else {
            for (var i = 0; i < 4; i++) {
                {
                    kb[i] = ka[i] ^ k[i + 4];
                }
            }
            this.camelliaF2(kb, this.SIGMA, 8);
            if (forEncryption) {
                this.kw[0] = k[0];
                this.kw[1] = k[1];
                this.kw[2] = k[2];
                this.kw[3] = k[3];
                this.roldqo32(45, k, 0, this.subkey, 16);
                this.roldq(15, k, 0, this.ke, 4);
                this.roldq(17, k, 0, this.subkey, 32);
                this.roldqo32(34, k, 0, this.subkey, 44);
                this.roldq(15, k, 4, this.subkey, 4);
                this.roldq(15, k, 4, this.ke, 0);
                this.roldq(30, k, 4, this.subkey, 24);
                this.roldqo32(34, k, 4, this.subkey, 36);
                this.roldq(15, ka, 0, this.subkey, 8);
                this.roldq(30, ka, 0, this.subkey, 20);
                this.ke[8] = ka[1];
                this.ke[9] = ka[2];
                this.ke[10] = ka[3];
                this.ke[11] = ka[0];
                this.roldqo32(49, ka, 0, this.subkey, 40);
                this.subkey[0] = kb[0];
                this.subkey[1] = kb[1];
                this.subkey[2] = kb[2];
                this.subkey[3] = kb[3];
                this.roldq(30, kb, 0, this.subkey, 12);
                this.roldq(30, kb, 0, this.subkey, 28);
                this.roldqo32(51, kb, 0, this.kw, 4);
            }
            else {
                this.kw[4] = k[0];
                this.kw[5] = k[1];
                this.kw[6] = k[2];
                this.kw[7] = k[3];
                this.decroldqo32(45, k, 0, this.subkey, 28);
                this.decroldq(15, k, 0, this.ke, 4);
                this.decroldq(17, k, 0, this.subkey, 12);
                this.decroldqo32(34, k, 0, this.subkey, 0);
                this.decroldq(15, k, 4, this.subkey, 40);
                this.decroldq(15, k, 4, this.ke, 8);
                this.decroldq(30, k, 4, this.subkey, 20);
                this.decroldqo32(34, k, 4, this.subkey, 8);
                this.decroldq(15, ka, 0, this.subkey, 36);
                this.decroldq(30, ka, 0, this.subkey, 24);
                this.ke[2] = ka[1];
                this.ke[3] = ka[2];
                this.ke[0] = ka[3];
                this.ke[1] = ka[0];
                this.decroldqo32(49, ka, 0, this.subkey, 4);
                this.subkey[46] = kb[0];
                this.subkey[47] = kb[1];
                this.subkey[44] = kb[2];
                this.subkey[45] = kb[3];
                this.decroldq(30, kb, 0, this.subkey, 32);
                this.decroldq(30, kb, 0, this.subkey, 16);
                this.roldqo32(51, kb, 0, this.kw, 0);
            }
        }
        this.initialized = true;
    }
    ;
    /**
     * IV for CBC encryption.
     *
     * Must be 16 bytes!
     *
     * @param {Buffer} iv - ```Buffer```
     */
    set_iv(iv) {
        if (iv.length != 16) {
            throw Error("IV must be 16 bytes long");
        }
        this.iv = iv;
        this.iv_set = true;
    }
    ;
    /**
     * Key for encryption.
     *
     * Only lengths of 16, 24 or 32 bytes allowed!
     *
     * @param {Buffer} key - ```Buffer```
     */
    set_key(key) {
        switch ((key.length)) {
            case 16:
                this._keyis128 = true;
                break;
            case 24:
                this._keyis128 = false;
                break;
            case 32:
                this._keyis128 = false;
                break;
            default:
                throw Error("key sizes are only 16/24/32 bytes.");
        }
        this.key = key;
        this.key_set = true;
    }
    ;
    encrypt_block(block, last_block) {
        if (!this.initialized) {
            this.setkey(true, this.key);
        }
        if (last_block) {
            block = padd_block(block);
        }
        if (this.iv_set == true) {
            block = xor(block, this.iv);
        }
        const return_block = this.processBlock(block);
        if (this.iv_set == true) {
            this.iv = return_block;
        }
        return return_block;
    }
    ;
    decrypt_block(block, last_block) {
        if (!this.initialized) {
            this.setkey(false, this.key);
        }
        if (this.iv_set == true) {
            if (this.previous_block != undefined) {
                this.iv = this.previous_block;
            }
        }
        this.previous_block = block;
        var return_block = this.processBlock(block);
        if (this.iv_set == true) {
            return_block = xor(return_block, this.iv);
        }
        if (last_block) {
            var padd_value = align(return_block.length, 16);
            return removePKCSPadding(return_block, padd_value, true);
        }
        return return_block;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If padding number is not set, uses PKCS padding.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {number} padding - ```number``` defaults to 0 for PKCS or can use a value
     * @returns ```Buffer```
     */
    encrypt(data_in, padding = 0) {
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        this.setkey(true, this.key);
        const block_size = 16;
        var data = data_in;
        var padd_value = padding;
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            if (padding == 0) {
                padd_value = to_padd;
            }
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0; index < data.length / block_size; index++) {
            var block = data.subarray((index * block_size), (index + 1) * block_size);
            if (this.iv_set == true) {
                block = xor(block, this.iv);
            }
            const return_block = this.processBlock(block);
            if (this.iv_set == true) {
                this.iv = return_block;
            }
            return_buff.push(return_block);
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    /**
     * If IV is not set, runs in ECB mode.
     *
     * If IV was set, runs in CBC mode.
     *
     * If remove_padding is ``number``, will check the last block and remove padded number.
     *
     * If remove_padding is ``true``, will remove PKCS padding on last block.
     *
     * @param {Buffer} data_in - ```Buffer```
     * @param {boolean|number} remove_padding - Will check the last block and remove padded ``number``. Will remove PKCS if ``true``
     * @returns ```Buffer```
     */
    decrypt(data_in, remove_padding = true) {
        if (this.key_set != true) {
            throw Error("Please set key first");
        }
        this.setkey(false, this.key);
        const block_size = 16;
        var data = data_in;
        var padd_value = align(data.length, block_size);
        if (typeof remove_padding == 'number') {
            padd_value = remove_padding & 0xFF;
        }
        const return_buff = [];
        if (data.length % block_size != 0) {
            var to_padd = block_size - (data.length % block_size);
            var paddbuffer = Buffer.alloc(to_padd, padd_value & 0xFF);
            data = Buffer.concat([data_in, paddbuffer]);
        }
        for (let index = 0, amount = Math.ceil(data.length / block_size); index < amount; index++) {
            var block = data.subarray((index * block_size), (index + 1) * block_size);
            if (this.iv_set == true) {
                if (this.previous_block != undefined) {
                    this.iv = this.previous_block;
                }
            }
            this.previous_block = block;
            var return_block = this.processBlock(block);
            if (this.iv_set == true) {
                return_block = xor(return_block, this.iv);
            }
            if ((remove_padding != false) && (index == (amount - 1))) {
                return_block = removePKCSPadding(return_block, padd_value, remove_padding);
                return_buff.push(return_block);
            }
            else {
                return_buff.push(return_block);
            }
        }
        var final_buffer = Buffer.concat(return_buff);
        this.iv_set = false;
        return final_buffer;
    }
    ;
    processBlock(__in) {
        if (!this.initialized) {
            throw Error("Camellia is not initialized");
        }
        if (this._keyis128) {
            return this.processBlock128(__in);
        }
        else {
            return this.processBlock192or256(__in);
        }
    }
    ;
    processBlock128(__in) {
        for (var i = 0; i < 4; i++) {
            {
                this.state[i] = this.bytes2int(__in, (i * 4));
                this.state[i] ^= this.kw[i];
            }
        }
        this.camelliaF2(this.state, this.subkey, 0);
        this.camelliaF2(this.state, this.subkey, 4);
        this.camelliaF2(this.state, this.subkey, 8);
        this.camelliaFLs(this.state, this.ke, 0);
        this.camelliaF2(this.state, this.subkey, 12);
        this.camelliaF2(this.state, this.subkey, 16);
        this.camelliaF2(this.state, this.subkey, 20);
        this.camelliaFLs(this.state, this.ke, 4);
        this.camelliaF2(this.state, this.subkey, 24);
        this.camelliaF2(this.state, this.subkey, 28);
        this.camelliaF2(this.state, this.subkey, 32);
        this.state[2] ^= this.kw[4];
        this.state[3] ^= this.kw[5];
        this.state[0] ^= this.kw[6];
        this.state[1] ^= this.kw[7];
        var out = Buffer.alloc(16);
        this.int2bytes(this.state[2], out, 0);
        this.int2bytes(this.state[3], out, 4);
        this.int2bytes(this.state[0], out, 8);
        this.int2bytes(this.state[1], out, 12);
        return out;
    }
    ;
    processBlock192or256(__in) {
        for (var i = 0; i < 4; i++) {
            {
                this.state[i] = this.bytes2int(__in, (i * 4));
                this.state[i] ^= this.kw[i];
            }
        }
        this.camelliaF2(this.state, this.subkey, 0);
        this.camelliaF2(this.state, this.subkey, 4);
        this.camelliaF2(this.state, this.subkey, 8);
        this.camelliaFLs(this.state, this.ke, 0);
        this.camelliaF2(this.state, this.subkey, 12);
        this.camelliaF2(this.state, this.subkey, 16);
        this.camelliaF2(this.state, this.subkey, 20);
        this.camelliaFLs(this.state, this.ke, 4);
        this.camelliaF2(this.state, this.subkey, 24);
        this.camelliaF2(this.state, this.subkey, 28);
        this.camelliaF2(this.state, this.subkey, 32);
        this.camelliaFLs(this.state, this.ke, 8);
        this.camelliaF2(this.state, this.subkey, 36);
        this.camelliaF2(this.state, this.subkey, 40);
        this.camelliaF2(this.state, this.subkey, 44);
        this.state[2] ^= this.kw[4];
        this.state[3] ^= this.kw[5];
        this.state[0] ^= this.kw[6];
        this.state[1] ^= this.kw[7];
        var out = Buffer.alloc(16);
        this.int2bytes(this.state[2], out, 0);
        this.int2bytes(this.state[3], out, 4);
        this.int2bytes(this.state[0], out, 8);
        this.int2bytes(this.state[1], out, 12);
        return out;
    }
    ;
}

class JPExtData {
    constructor(type, data) {
        this.type = type;
        this.data = data;
    }
}
class JPExtensionCodec {
    constructor(extension) {
        // custom extensions
        this.encoders = [];
        this.encodersAsync = [];
        this.decoders = [];
        this.decodersAsync = [];
        if (extension) {
            this.register(extension);
        }
    }
    ;
    register(extension) {
        // custom extensions
        if ((extension.type < 0 || extension.type > 0xCF)) {
            throw new Error(`Type EXT number is outside of allowed range (0x0 - 0xCF but got 0x${extension.type.toString(16).padStart(2, "0")})`);
        }
        this.encoders[extension.type] = extension.encode;
        this.decoders[extension.type] = extension.decode;
        this.encodersAsync[extension.type] = extension.encodeAsync;
        this.decodersAsync[extension.type] = extension.decodeAsync;
    }
    ;
    tryToEncode(object, encoder, context) {
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
    }
    ;
    async tryToEncodeAsync(object, encoder, context) {
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
    }
    ;
    decode(data, decoder, type, context) {
        const decodeExt = this.decoders[type];
        if (decodeExt) {
            return decodeExt(data, decoder, type, context);
        }
        else {
            // decode() does not fail, returns ExtData instead.
            return new JPExtData(type, data.data);
        }
    }
    async decodeAsync(data, decoder, type, context) {
        const decodeExt = this.decodersAsync[type];
        if (decodeExt) {
            return await decodeExt(data, decoder, type, context);
        }
        else {
            // decode() does not fail, returns ExtData instead.
            return new JPExtData(type, data.data);
        }
    }
}
JPExtensionCodec.defaultCodec = new JPExtensionCodec();

var version = "1.0.6";
var pack = {
	version: version};

const GROWTHINCREMENT_DEFAULT = 0x1000000;
/**
 * Get build version string.
 *
 * @returns {{VERSION_MAJOR: ubyte, VERSION_MINOR: ubyte}}
 */
function GetVer() {
    const ver = /(\d+)(\.)(\d+)(\.)(\d+)/g.exec(pack.version);
    return {
        VERSION_MAJOR: parseInt(ver ? ver[1] : "0"),
        VERSION_MINOR: parseInt(ver ? ver[3] : "0"),
    };
}
const { 
/**
 * Build verion number to check the file creation params
 */
VERSION_MAJOR, 
/**
 * Build verion number to check the file creation params
 */
VERSION_MINOR } = GetVer();
/**
 * Build verion number to check the file creation params
 */
const VERSION_NUMBER = parseFloat(`${VERSION_MAJOR}.${VERSION_MINOR}`);
/**
 * Max Buffer size.
 *
 * @returns {number}
 */
function MAX_LENGTH() {
    return node_buffer.constants.MAX_LENGTH;
}
/**
 * Max Buffer size for this system.
 */
const MAX_BUFFER = MAX_LENGTH() || 0x100000000;
function isFloat32Safe(value) {
    if (!Number.isFinite(value))
        return true; // Infinity, -Infinity, NaN all store fine
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
function peakBytesSync(filePath, numBytes) {
    const fd = fs.openSync(filePath, 'r');
    const buffer = Buffer.alloc(numBytes);
    try {
        fs.readSync(fd, buffer, 0, numBytes, 0);
    }
    finally {
        fs.closeSync(fd);
    }
    return buffer;
}
/**
 * Checks if a file exisits
 *
 * @param {string} filePath
 * @returns {boolean}
 */
function fileExists(filePath) {
    try {
        fs.accessSync(filePath, fs.constants.F_OK);
        return true; // File exists
    }
    catch (error) {
        return false;
    }
}
/**
 * Decompress a framed deflate-compressed file.
 */
function inflateFileSync(inReader, outWriter) {
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
}
/**
 * Decompress a framed deflate-compressed file.
 */
async function inflateFileAsync(inReader, outWriter) {
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
}
/**
 * Compress a Buffer using Deflate, framed with [length][chunk] blocks.
 */
function deflateBuffer(inWriter) {
    let bytesToProcess = inWriter.size;
    let bytesStart = 0;
    let bytesRead = 0;
    const buffers = [];
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
}
/**
 * Compress a Buffer using Deflate, framed with [length][chunk] blocks.
 */
async function deflateBufferAsync(inWriter) {
    let bytesToProcess = inWriter.size;
    let bytesStart = 0;
    let bytesRead = 0;
    const buffers = [];
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
}
/**
 * Decompress a framed deflate-compressed buffer.
 */
function inflateBuffer(bw) {
    const startingOff = bw.offset;
    const size = bw.size;
    const totalBuffer = size - startingOff;
    let bytesRead = 0;
    const buffers = [];
    while (bytesRead < totalBuffer) {
        const chunkLen = bw.readUInt32LE();
        bytesRead += 4;
        const compressed = bw.extract(chunkLen);
        bytesRead += chunkLen;
        const decompressed = zlib.inflateSync(compressed);
        buffers.push(decompressed);
    }
    return Buffer.concat(buffers);
}
/**
 * Decompress a framed deflate-compressed buffer.
 */
async function inflateBufferAsync(bw) {
    const startingOff = bw.offset;
    const size = bw.size;
    const totalBuffer = size - startingOff;
    let bytesRead = 0;
    const buffers = [];
    while (bytesRead < totalBuffer) {
        const chunkLen = await bw.readUInt32LE();
        bytesRead += 4;
        const compressed = await bw.extract(chunkLen);
        bytesRead += chunkLen;
        const decompressed = zlib.inflateSync(compressed);
        buffers.push(decompressed);
    }
    return Buffer.concat(buffers);
}
function isArrayBufferLike(buffer) {
    return (buffer instanceof ArrayBuffer || (typeof SharedArrayBuffer !== "undefined" && buffer instanceof SharedArrayBuffer));
}
function ensureBuffer(buffer) {
    if (buffer instanceof Buffer) {
        return buffer;
    }
    else if (buffer instanceof Uint8Array) {
        return Buffer.from(buffer);
    }
    else if (ArrayBuffer.isView(buffer)) {
        return Buffer.from(buffer.buffer);
    }
    else if (isArrayBufferLike(buffer)) {
        return Buffer.from(buffer);
    }
    else {
        // ArrayLike<number>
        return Buffer.from(buffer);
    }
}
/**
 * Internal index for values.
 */
exports.JPType = void 0;
(function (JPType) {
    // 0x00 - 0x7F positive fixint 
    JPType[JPType["OBJECT_0"] = 128] = "OBJECT_0";
    JPType[JPType["OBJECT_1"] = 129] = "OBJECT_1";
    JPType[JPType["OBJECT_2"] = 130] = "OBJECT_2";
    JPType[JPType["OBJECT_3"] = 131] = "OBJECT_3";
    JPType[JPType["OBJECT_4"] = 132] = "OBJECT_4";
    JPType[JPType["OBJECT_5"] = 133] = "OBJECT_5";
    JPType[JPType["OBJECT_6"] = 134] = "OBJECT_6";
    JPType[JPType["OBJECT_7"] = 135] = "OBJECT_7";
    JPType[JPType["OBJECT_8"] = 136] = "OBJECT_8";
    JPType[JPType["OBJECT_9"] = 137] = "OBJECT_9";
    JPType[JPType["OBJECT_10"] = 138] = "OBJECT_10";
    JPType[JPType["OBJECT_11"] = 139] = "OBJECT_11";
    JPType[JPType["OBJECT_12"] = 140] = "OBJECT_12";
    JPType[JPType["OBJECT_13"] = 141] = "OBJECT_13";
    JPType[JPType["OBJECT_14"] = 142] = "OBJECT_14";
    JPType[JPType["OBJECT_15"] = 143] = "OBJECT_15";
    JPType[JPType["ARRAY_0"] = 144] = "ARRAY_0";
    JPType[JPType["ARRAY_1"] = 145] = "ARRAY_1";
    JPType[JPType["ARRAY_2"] = 146] = "ARRAY_2";
    JPType[JPType["ARRAY_3"] = 147] = "ARRAY_3";
    JPType[JPType["ARRAY_4"] = 148] = "ARRAY_4";
    JPType[JPType["ARRAY_5"] = 149] = "ARRAY_5";
    JPType[JPType["ARRAY_6"] = 150] = "ARRAY_6";
    JPType[JPType["ARRAY_7"] = 151] = "ARRAY_7";
    JPType[JPType["ARRAY_8"] = 152] = "ARRAY_8";
    JPType[JPType["ARRAY_9"] = 153] = "ARRAY_9";
    JPType[JPType["ARRAY_10"] = 154] = "ARRAY_10";
    JPType[JPType["ARRAY_11"] = 155] = "ARRAY_11";
    JPType[JPType["ARRAY_12"] = 156] = "ARRAY_12";
    JPType[JPType["ARRAY_13"] = 157] = "ARRAY_13";
    JPType[JPType["ARRAY_14"] = 158] = "ARRAY_14";
    JPType[JPType["ARRAY_15"] = 159] = "ARRAY_15";
    JPType[JPType["KEY_0"] = 160] = "KEY_0";
    JPType[JPType["KEY_1"] = 161] = "KEY_1";
    JPType[JPType["KEY_2"] = 162] = "KEY_2";
    JPType[JPType["KEY_3"] = 163] = "KEY_3";
    JPType[JPType["KEY_4"] = 164] = "KEY_4";
    JPType[JPType["KEY_5"] = 165] = "KEY_5";
    JPType[JPType["KEY_6"] = 166] = "KEY_6";
    JPType[JPType["KEY_7"] = 167] = "KEY_7";
    JPType[JPType["KEY_8"] = 168] = "KEY_8";
    JPType[JPType["KEY_9"] = 169] = "KEY_9";
    JPType[JPType["KEY_10"] = 170] = "KEY_10";
    JPType[JPType["KEY_11"] = 171] = "KEY_11";
    JPType[JPType["KEY_12"] = 172] = "KEY_12";
    JPType[JPType["KEY_13"] = 173] = "KEY_13";
    JPType[JPType["KEY_14"] = 174] = "KEY_14";
    JPType[JPType["KEY_15"] = 175] = "KEY_15";
    JPType[JPType["STR_0"] = 176] = "STR_0";
    JPType[JPType["STR_1"] = 177] = "STR_1";
    JPType[JPType["STR_2"] = 178] = "STR_2";
    JPType[JPType["STR_3"] = 179] = "STR_3";
    JPType[JPType["STR_4"] = 180] = "STR_4";
    JPType[JPType["STR_5"] = 181] = "STR_5";
    JPType[JPType["STR_6"] = 182] = "STR_6";
    JPType[JPType["STR_7"] = 183] = "STR_7";
    JPType[JPType["STR_8"] = 184] = "STR_8";
    JPType[JPType["STR_9"] = 185] = "STR_9";
    JPType[JPType["STR_10"] = 186] = "STR_10";
    JPType[JPType["STR_11"] = 187] = "STR_11";
    JPType[JPType["STR_12"] = 188] = "STR_12";
    JPType[JPType["STR_13"] = 189] = "STR_13";
    JPType[JPType["STR_14"] = 190] = "STR_14";
    JPType[JPType["STR_15"] = 191] = "STR_15";
    JPType[JPType["NULL"] = 192] = "NULL";
    JPType[JPType["UNDEFINED"] = 193] = "UNDEFINED";
    JPType[JPType["BOOL_FALSE"] = 194] = "BOOL_FALSE";
    JPType[JPType["BOOL_TRUE"] = 195] = "BOOL_TRUE";
    JPType[JPType["FINISHED"] = 196] = "FINISHED";
    JPType[JPType["LIST_END"] = 197] = "LIST_END";
    JPType[JPType["UNUSED_C6"] = 198] = "UNUSED_C6";
    JPType[JPType["OBJECT8"] = 199] = "OBJECT8";
    JPType[JPType["OBJECT16"] = 200] = "OBJECT16";
    JPType[JPType["OBJECT32"] = 201] = "OBJECT32";
    JPType[JPType["FLOAT32"] = 202] = "FLOAT32";
    JPType[JPType["FLOAT64"] = 203] = "FLOAT64";
    JPType[JPType["UINT_8"] = 204] = "UINT_8";
    JPType[JPType["UINT_16"] = 205] = "UINT_16";
    JPType[JPType["UINT_32"] = 206] = "UINT_32";
    JPType[JPType["UINT_64"] = 207] = "UINT_64";
    JPType[JPType["INT_8"] = 208] = "INT_8";
    JPType[JPType["INT_16"] = 209] = "INT_16";
    JPType[JPType["INT_32"] = 210] = "INT_32";
    JPType[JPType["INT_64"] = 211] = "INT_64";
    JPType[JPType["KEY8"] = 212] = "KEY8";
    JPType[JPType["KEY16"] = 213] = "KEY16";
    JPType[JPType["KEY32"] = 214] = "KEY32";
    JPType[JPType["STR8"] = 215] = "STR8";
    JPType[JPType["STR16"] = 216] = "STR16";
    JPType[JPType["STR32"] = 217] = "STR32";
    JPType[JPType["ARRAY8"] = 218] = "ARRAY8";
    JPType[JPType["ARRAY16"] = 219] = "ARRAY16";
    JPType[JPType["ARRAY32"] = 220] = "ARRAY32";
    JPType[JPType["EXT8"] = 221] = "EXT8";
    JPType[JPType["EXT16"] = 222] = "EXT16";
    JPType[JPType["EXT32"] = 223] = "EXT32";
    // 0xE0 - 0xFF negative fixint 
})(exports.JPType || (exports.JPType = {}));
/**
 * Internal index for ext values.
 */
exports.JPExtType = void 0;
(function (JPExtType) {
    // 0xD0 - 0xFF are reserve extend numbers
    JPExtType[JPExtType["Maps"] = 238] = "Maps";
    JPExtType[JPExtType["Sets"] = 239] = "Sets";
    JPExtType[JPExtType["Symbol"] = 240] = "Symbol";
    JPExtType[JPExtType["RegEx"] = 241] = "RegEx";
    JPExtType[JPExtType["BigUint64Array"] = 242] = "BigUint64Array";
    JPExtType[JPExtType["BigInt64Array"] = 243] = "BigInt64Array";
    JPExtType[JPExtType["Float64Array"] = 244] = "Float64Array";
    JPExtType[JPExtType["Float32Array"] = 245] = "Float32Array";
    JPExtType[JPExtType["Float16Array"] = 246] = "Float16Array";
    JPExtType[JPExtType["Int32Array"] = 247] = "Int32Array";
    JPExtType[JPExtType["Uint32Array"] = 248] = "Uint32Array";
    JPExtType[JPExtType["Uint16Array"] = 249] = "Uint16Array";
    JPExtType[JPExtType["Int16Array"] = 250] = "Int16Array";
    JPExtType[JPExtType["Int8Array"] = 251] = "Int8Array";
    JPExtType[JPExtType["Uint8Array"] = 252] = "Uint8Array";
    JPExtType[JPExtType["Uint8ClampedArray"] = 253] = "Uint8ClampedArray";
    JPExtType[JPExtType["Buffer"] = 254] = "Buffer";
    JPExtType[JPExtType["Date"] = 255] = "Date"; // MSGPACK Standard
})(exports.JPExtType || (exports.JPExtType = {}));
/**
 * For creating a unique string list
 */
class stringList {
    /**
     * For creating a unique string list
     *
     * @param {string[]?} stringArray
     */
    constructor(stringArray) {
        this.array = [];
        this.set = new Set();
        if (stringArray) {
            this.array = stringArray;
            this.set = new Set(stringArray);
        }
        else {
            this.array = [];
            this.set = new Set();
        }
    }
    ;
    /**
     * Add string
     *
     * @param {string} value
     * @returns {number} index
     */
    add(value) {
        if (!this.set.has(value)) {
            this.set.add(value);
            this.array.push(value);
        }
        return this.getIndex(value);
    }
    ;
    /**
     * Gets the string from the index
     *
     * @param {number} value
     * @returns {string}
     */
    get(value) {
        return this.array[value];
    }
    ;
    /**
     * Shouldn't ever use!
     *
     * @param {string} value
     */
    remove(value) {
        if (this.set.has(value)) {
            this.set.delete(value);
            // Find the index of the value in the array and remove it
            const index = this.array.indexOf(value);
            if (index !== -1) {
                this.array.splice(index, 1);
            }
        }
    }
    ;
    /**
     * Gets the index for the string
     *
     * @param {string} value
     * @returns {number} index
     */
    getIndex(value) {
        return this.array.indexOf(value);
    }
    ;
    /**
     * returns data as an array
     *
     * @returns {string[]} string array
     */
    getValues() {
        return this.array;
    }
    ;
    /**
     * Check the set has the value
     *
     * @param {string} value
     * @returns {boolean} if the value is in the dataset
     */
    has(value) {
        return this.set.has(value);
    }
    ;
}
class JPBase {
    constructor() {
        ////////////////
        //  BUFFERS   //
        ////////////////
        /**
         * Buffer for header data.
         */
        this.headerBuffer = null;
        ////////////////
        //  WRITERS   //
        ////////////////
        this.useFile = false;
        this.valueWriter = null;
        this.strWriter = null;
        this.compWriter = null;
        ////////////////
        //  READERS   //
        ////////////////
        this.fileReader = null;
        this.valueReader = null;
        this.strReader = null;
        this.compReader = null;
        ////////////////
        //   SIZES    //
        ////////////////
        /**
         * Buffer size. 16mbs
         */
        this.growthIncrement = GROWTHINCREMENT_DEFAULT;
        /**
         * Internal size.
         */
        this._HEADER_SIZE = 0;
        /**
         * Internal size.
         */
        this._VALUE_SIZE = 0n;
        /**
         * Internal size.
         */
        this._STR_SIZE = 0n;
        /**
         * Internal size.
         */
        this._DATA_SIZE = 0n;
        ////////////////
        //   FLAGS    //
        ////////////////
        /**
        * Flags for file header.
        */
        this.flags = {
            LargeFile: 0,
            Compressed: 0,
            Crc32: 0,
            Encrypted: 0,
            EncryptionExcluded: 0,
            KeyStripped: 0
        };
        ////////////////////
        // EXTRA HEADERS  //
        ////////////////////
        /**
         * Encryption key For decryption.
         */
        this._encryptionKey = 0;
        /**
         * Check hash value.
         */
        this._CRC32 = 0;
        ////////////////////
        // SHARED OBJECTS //
        ////////////////////
        /**
         * Object keys for when `stripKeys` was enabled in encoding.
         *
         * This array MUST be passed to decoder for the file to be decoded.
         */
        this.keysArray = [];
        this.entered = false;
        this.fileName = "";
        this.errored = false;
        this.errorMessage = "";
    }
    /**
     * Size of the header buffer.
     */
    set HEADER_SIZE(value) {
        this._HEADER_SIZE = value;
    }
    ;
    /**
     * Size of the header buffer.
     */
    get HEADER_SIZE() {
        if (this._HEADER_SIZE != 0) {
            return this._HEADER_SIZE;
        }
        else if (this.headerBuffer != null) {
            this._HEADER_SIZE = this.headerBuffer.length;
            return this.headerBuffer.length;
        }
        else {
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
    }
    ;
    /**
     * The size of the section that has values data.
     */
    set VALUE_SIZE(value) {
        this._VALUE_SIZE = BigInt(value);
    }
    ;
    /**
      * The size of the section that has every other type of data.
      */
    get VALUE_SIZE() {
        if (this._VALUE_SIZE != 0n) {
            return this._VALUE_SIZE;
        }
        else if (this.valueWriter != null) {
            this._VALUE_SIZE = BigInt(this.valueWriter.offset);
            return this._VALUE_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * The size of the section that has string / key data.
     */
    set STR_SIZE(value) {
        this._STR_SIZE = BigInt(value);
    }
    ;
    /**
     * The size of the section that has string / key data.
     */
    get STR_SIZE() {
        if (this._STR_SIZE != 0n) {
            return this._STR_SIZE;
        }
        else if (this.strWriter != null) {
            this._STR_SIZE = BigInt(this.strWriter.offset);
            return this._STR_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    set DATA_SIZE(value) {
        this._DATA_SIZE = BigInt(value);
    }
    ;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    get DATA_SIZE() {
        if (this._DATA_SIZE != 0n) {
            return this._DATA_SIZE;
        }
        else if (this._VALUE_SIZE != 0n && this._STR_SIZE != 0n) {
            this._DATA_SIZE = BigInt(this._VALUE_SIZE + this._STR_SIZE);
            return this._DATA_SIZE;
        }
        else if (this.strWriter != null && this.valueWriter != null) {
            this._DATA_SIZE = BigInt(this.valueWriter.size + this.strWriter.length);
            return this._DATA_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * For files over 4 gigs.
     *
     * @param {bit} bit flag
     */
    set LargeFile(bit) {
        this.flags.LargeFile = (bit & 1);
    }
    ;
    /**
     * For files over 4 gigs.
     *
     * @returns {bit} flag
     */
    get LargeFile() {
        return this.flags.LargeFile;
    }
    ;
    /**
     * If the data is zlib compressed.
     *
     * @returns {bit} flag
     */
    get Compressed() {
        return this.flags.Compressed;
    }
    ;
    /**
     * If the data is zlib compressed.
     *
     * @param {bit} bit flag
     */
    set Compressed(bit) {
        this.flags.Compressed = (bit & 1);
    }
    ;
    /**
     * If a CRC32 is done on the data.
     *
     * @returns {bit} flag
     */
    get Crc32() {
        return this.flags.Crc32;
    }
    ;
    /**
     * If a CRC32 is done on the data.
     *
     * @param {bit} bit flag
     */
    set Crc32(bit) {
        this.flags.Crc32 = (bit & 1);
    }
    ;
    /**
     * If the file is encrypted.
     *
     * @returns {bit} flag
     */
    get Encrypted() {
        return this.flags.Encrypted;
    }
    ;
    /**
     * If the file is encrypted.
     *
     * @param {bit} bit flag
     */
    set Encrypted(bit) {
        this.flags.Encrypted = (bit & 1);
    }
    ;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @returns {bit} flag
     */
    get EncryptionExcluded() {
        return this.flags.EncryptionExcluded;
    }
    ;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @param {bit} bit flag
     */
    set EncryptionExcluded(bit) {
        this.flags.EncryptionExcluded = (bit & 1);
    }
    ;
    /**
     * If the object keys are removed from the file.
     *
     * @returns {bit} flag
     */
    get KeyStripped() {
        return this.flags.KeyStripped;
    }
    ;
    /**
     * If the object keys are removed from the file.
     *
     * @param {bit} bit flag
     */
    set KeyStripped(bit) {
        this.flags.KeyStripped = (bit & 1);
    }
    ;
    /**
     * Encryption value. For decryption.
     */
    set encryptionKey(value) {
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
    set CRC32(value) {
        this._CRC32 = value;
    }
    /**
     * Check hash value.
     */
    get CRC32() {
        return this._CRC32;
    }
    throwError(errorMessage) {
        this.errored = true;
        this.errorMessage += errorMessage;
        throw new Error(this.errorMessage);
    }
    ;
    addError(errorMessage) {
        this.errored = true;
        this.errorMessage += errorMessage;
        console.warn(this.errorMessage);
    }
    ;
}
class JPBaseAsync {
    constructor() {
        ////////////////
        //  BUFFERS   //
        ////////////////
        /**
         * Buffer for header data.
         */
        this.headerBuffer = null;
        ////////////////
        //  WRITERS   //
        ////////////////
        this.useFile = false;
        this.valueWriterAsync = null;
        this.strWriterAsync = null;
        this.compWriterAsync = null;
        ////////////////
        //  READERS   //
        ////////////////
        this.fileReaderAsync = null;
        this.valueReaderAsync = null;
        this.strReaderAsync = null;
        this.compReaderAsync = null;
        ////////////////
        //   SIZES    //
        ////////////////
        /**
         * Buffer size. 16mbs
         */
        this.growthIncrement = GROWTHINCREMENT_DEFAULT;
        /**
         * Internal size.
         */
        this._HEADER_SIZE = 0;
        /**
         * Internal size.
         */
        this._VALUE_SIZE = 0n;
        /**
         * Internal size.
         */
        this._STR_SIZE = 0n;
        /**
         * Internal size.
         */
        this._DATA_SIZE = 0n;
        ////////////////
        //   FLAGS    //
        ////////////////
        /**
        * Flags for file header.
        */
        this.flags = {
            LargeFile: 0,
            Compressed: 0,
            Crc32: 0,
            Encrypted: 0,
            EncryptionExcluded: 0,
            KeyStripped: 0
        };
        ////////////////////
        // EXTRA HEADERS  //
        ////////////////////
        /**
         * Encryption key For decryption.
         */
        this._encryptionKey = 0;
        /**
         * Check hash value.
         */
        this._CRC32 = 0;
        ////////////////////
        // SHARED OBJECTS //
        ////////////////////
        /**
         * Object keys for when `stripKeys` was enabled in encoding.
         *
         * This array MUST be passed to decoder for the file to be decoded.
         */
        this.keysArray = [];
        this.entered = false;
        this.fileName = "";
        this.errored = false;
        this.errorMessage = "";
    }
    /**
     * Size of the header buffer.
     */
    set HEADER_SIZE(value) {
        this._HEADER_SIZE = value;
    }
    ;
    /**
     * Size of the header buffer.
     */
    get HEADER_SIZE() {
        if (this._HEADER_SIZE != 0) {
            return this._HEADER_SIZE;
        }
        else if (this.headerBuffer != null) {
            this._HEADER_SIZE = this.headerBuffer.length;
            return this.headerBuffer.length;
        }
        else {
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
    }
    ;
    /**
     * The size of the section that has values data.
     */
    set VALUE_SIZE(value) {
        this._VALUE_SIZE = BigInt(value);
    }
    ;
    /**
      * The size of the section that has every other type of data.
      */
    get VALUE_SIZE() {
        if (this._VALUE_SIZE != 0n) {
            return this._VALUE_SIZE;
        }
        else if (this.valueWriterAsync != null) {
            this._VALUE_SIZE = BigInt(this.valueWriterAsync.offset);
            return this._VALUE_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * The size of the section that has string / key data.
     */
    set STR_SIZE(value) {
        this._STR_SIZE = BigInt(value);
    }
    ;
    /**
     * The size of the section that has string / key data.
     */
    get STR_SIZE() {
        if (this._STR_SIZE != 0n) {
            return this._STR_SIZE;
        }
        else if (this.strWriterAsync != null) {
            this._STR_SIZE = BigInt(this.strWriterAsync.offset);
            return this._STR_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    set DATA_SIZE(value) {
        this._DATA_SIZE = BigInt(value);
    }
    ;
    /**
     * Total value size for both section, used when compressed or encrypted.
     */
    get DATA_SIZE() {
        if (this._DATA_SIZE != 0n) {
            return this._DATA_SIZE;
        }
        else if (this._VALUE_SIZE != 0n && this._STR_SIZE != 0n) {
            this._DATA_SIZE = BigInt(this._VALUE_SIZE + this._STR_SIZE);
            return this._DATA_SIZE;
        }
        else if (this.strWriterAsync != null && this.valueWriterAsync != null) {
            this._DATA_SIZE = BigInt(this.valueWriterAsync.size + this.strWriterAsync.length);
            return this._DATA_SIZE;
        }
        else {
            return 0n;
        }
    }
    ;
    /**
     * For files over 4 gigs.
     *
     * @param {bit} bit flag
     */
    set LargeFile(bit) {
        this.flags.LargeFile = (bit & 1);
    }
    ;
    /**
     * For files over 4 gigs.
     *
     * @returns {bit} flag
     */
    get LargeFile() {
        return this.flags.LargeFile;
    }
    ;
    /**
     * If the data is zlib compressed.
     *
     * @returns {bit} flag
     */
    get Compressed() {
        return this.flags.Compressed;
    }
    ;
    /**
     * If the data is zlib compressed.
     *
     * @param {bit} bit flag
     */
    set Compressed(bit) {
        this.flags.Compressed = (bit & 1);
    }
    ;
    /**
     * If a CRC32 is done on the data.
     *
     * @returns {bit} flag
     */
    get Crc32() {
        return this.flags.Crc32;
    }
    ;
    /**
     * If a CRC32 is done on the data.
     *
     * @param {bit} bit flag
     */
    set Crc32(bit) {
        this.flags.Crc32 = (bit & 1);
    }
    ;
    /**
     * If the file is encrypted.
     *
     * @returns {bit} flag
     */
    get Encrypted() {
        return this.flags.Encrypted;
    }
    ;
    /**
     * If the file is encrypted.
     *
     * @param {bit} bit flag
     */
    set Encrypted(bit) {
        this.flags.Encrypted = (bit & 1);
    }
    ;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @returns {bit} flag
     */
    get EncryptionExcluded() {
        return this.flags.EncryptionExcluded;
    }
    ;
    /**
     * If the file's encryption key is not kept within the file.
     *
     * @param {bit} bit flag
     */
    set EncryptionExcluded(bit) {
        this.flags.EncryptionExcluded = (bit & 1);
    }
    ;
    /**
     * If the object keys are removed from the file.
     *
     * @returns {bit} flag
     */
    get KeyStripped() {
        return this.flags.KeyStripped;
    }
    ;
    /**
     * If the object keys are removed from the file.
     *
     * @param {bit} bit flag
     */
    set KeyStripped(bit) {
        this.flags.KeyStripped = (bit & 1);
    }
    ;
    /**
     * Encryption value. For decryption.
     */
    set encryptionKey(value) {
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
    set CRC32(value) {
        this._CRC32 = value;
    }
    /**
     * Check hash value.
     */
    get CRC32() {
        return this._CRC32;
    }
    throwError(errorMessage) {
        this.errored = true;
        this.errorMessage += errorMessage;
        throw new Error(this.errorMessage);
    }
    ;
    addError(errorMessage) {
        this.errored = true;
        this.errorMessage += errorMessage;
        console.warn(this.errorMessage);
    }
    ;
}

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
function stringifyFix$1(_this, key) {
    if (key === undefined) {
        return "undefined";
    }
    else if (key instanceof RegExp) {
        const src = key.source;
        const flags = key.flags;
        return { regexSrc: src, regexFlags: flags };
    }
    else if (typeof key == "symbol") {
        const keyCheck = Symbol.keyFor(key);
        const global = !!keyCheck;
        var keyed = keyCheck ?? key.description;
        keyed = keyed ?? "";
        return { symbolGlobal: global, symbolKey: keyed };
    }
    else if (key instanceof Set) {
        const array = [];
        for (const item of key) {
            array.push(item);
        }
        return array;
    }
    else if (key instanceof Map) {
        return Array.from(key.entries());
    }
    else if (typeof key === "bigint") {
        const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);
        const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
        if (key >= MIN_SAFE && key <= MAX_SAFE) {
            return Number(key);
        }
        else {
            return key.toString();
        }
    }
    else {
        return key;
    }
}
const STATE_ARRAY$1 = "array";
const STATE_SET$1 = "set";
const STATE_MAP_KEY$1 = "map_key";
const STATE_MAP_VALUE$1 = "map_value";
const STATE_OBJECT_KEY$1 = "object_key";
const STATE_OBJECT_VALUE$1 = "object_value";
const mapKeyConverter$1 = (key) => {
    if (typeof key === "string" || typeof key === "number" || typeof key == "symbol") {
        return key;
    }
    throw new Error("The type of key must be string or number but " + typeof key);
};
let StackPool$1 = class StackPool {
    constructor() {
        this.stack = [];
        this.stackHeadPosition = -1;
    }
    get length() {
        return this.stackHeadPosition + 1;
    }
    ;
    top() {
        return this.stack[this.stackHeadPosition];
    }
    ;
    pushArrayState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_ARRAY$1;
        state.position = 0;
        state.size = size;
        state.array = new Array(size);
    }
    ;
    pushSetState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_SET$1;
        state.position = 0;
        state.size = size;
        state.set = new Set();
    }
    ;
    pushMapState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_MAP_KEY$1;
        state.readCount = 0;
        state.size = size;
        state.map = new Map();
    }
    ;
    pushObjectState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_OBJECT_KEY$1;
        state.readCount = 0;
        state.size = size;
        state.object = {};
    }
    ;
    getUninitializedStateFromPool() {
        this.stackHeadPosition++;
        if (this.stackHeadPosition === this.stack.length) {
            const partialState = {
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
            this.stack.push(partialState);
        }
        return this.stack[this.stackHeadPosition];
    }
    ;
    release(state) {
        const topStackState = this.stack[this.stackHeadPosition];
        if (topStackState !== state) {
            throw new Error("Invalid stack state. Released state is not on top of the stack.");
        }
        if (state.type === STATE_SET$1) {
            const partialState = state;
            partialState.size = 0;
            partialState.set = undefined;
            partialState.position = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_ARRAY$1) {
            const partialState = state;
            partialState.size = 0;
            partialState.array = undefined;
            partialState.position = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_MAP_KEY$1 || state.type === STATE_MAP_VALUE$1) {
            const partialState = state;
            partialState.size = 0;
            partialState.map = undefined;
            partialState.readCount = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_OBJECT_KEY$1 || state.type === STATE_OBJECT_VALUE$1) {
            const partialState = state;
            partialState.size = 0;
            partialState.object = undefined;
            partialState.readCount = 0;
            partialState.type = undefined;
        }
        this.stackHeadPosition--;
    }
    ;
    reset() {
        this.stack.length = 0;
        this.stackHeadPosition = -1;
    }
    ;
};
/**
 * Create with `DecoderOptions`
 */
class JPDecode extends JPBase {
    /**
     * Set up with basic options.
     *
     * @param {DecoderOptions?} options - options for decoding
     */
    constructor(options) {
        super();
        this.mapKeyConverter = mapKeyConverter$1;
        this.stack = new StackPool$1();
        this.stringsList = [];
        /**
         * Endianness. Defaults to `little`
         */
        this.endian = "little";
        /**
         * Converts return to valid JSON
         */
        this.makeJSON = false;
        /**
         * Ensures all 64 bit values return as `bigint`
         */
        this.enforceBigInt = false;
        /**
         * File Buffer
         */
        this.buffer = null;
        /**
         * Direct objects for any symbols that were encoded.
         */
        this.symbolList = [];
        /**
         * If a temp file was needed.
         */
        this.tempCreated = false;
        /**
         * If the file buffer has extensions types in use.
         */
        this.hasExtensions = false;
        /**
         * If the data is acceptable JSON data.
         */
        this.validJSON = true;
        /**
         * Computed CRC32 hash value.
         */
        this.CRC32Hash = 0;
        /**
         * CRC32 Hash on file.
         */
        this.CRC32OnFile = 0;
        this.extensionCodec = options?.extensionCodec ?? JPExtensionCodec.defaultCodec;
        this.context = options?.context; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined
        this.keysArray = options?.keysArray ? options.keysArray : [];
        this.encryptionKey = options?.encryptionKey ? options.encryptionKey : 0;
        this.enforceBigInt = options?.enforceBigInt ? options.enforceBigInt : false;
        this.makeJSON = options?.makeJSON ? options.makeJSON : false;
    }
    ;
    clone() {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // @ts-ignore
        const clone = new JPDecode({
            extensionCodec: this.extensionCodec,
            context: this.context,
            keysArray: this.keysArray,
            encryptionKey: this.encryptionKey,
            enforceBigInt: this.enforceBigInt,
            makeJSON: this.makeJSON,
        });
        clone.fileName = this.fileName;
        // TODO may need more
        return clone;
    }
    ;
    /**
     * Basic decoding, will run options that were set in constructor.
     *
     * If passed a `string`, will assume it is a file path to read the file from.
     *
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     *
     * @param bufferOrSourcePath - `Buffer` of the JamPack data or the file path to a JamPack file.
     */
    decode(bufferOrSourcePath) {
        if (this.entered) {
            const instance = this.clone();
            return instance.decode(bufferOrSourcePath);
        }
        if (typeof bufferOrSourcePath != "string") {
            this.setBuffer(bufferOrSourcePath);
        }
        else {
            this.fileName = bufferOrSourcePath;
            this.checkFilePath(this.fileName);
        }
        try {
            this.entered = true;
            this.reinitializeState();
            if (this.valueReader == null) {
                this.throwError(" No value reader set. " + this.fileName);
            }
            this.stringsList = this.createStringList();
            const object = this.doDecode(this.valueReader);
            if (this.tempCreated) {
                this.valueReader.deleteFile();
                this.valueReader.close();
            }
            if (this.makeJSON && !this.validJSON) {
                return JSON.parse(JSON.stringify(object, stringifyFix$1));
            }
            return object;
        }
        catch (err) {
            console.error(err);
            return;
        }
        finally {
            this.entered = false;
        }
    }
    ;
    checkFilePath(filePath) {
        var biTest = new BiReader(filePath, { enforceBigInt: this.enforceBigInt });
        const testBuffer = biTest.extract(40);
        biTest.close();
        biTest = new BiReader(testBuffer, { enforceBigInt: this.enforceBigInt });
        this.testHeader(biTest);
        biTest.close();
        if (!this.useFile) {
            this.buffer = fs.readFileSync(filePath);
        }
    }
    ;
    testHeader(br) {
        const MAGICS = br.uint16;
        if (!(MAGICS == 0x504A || MAGICS == 0x4A50)) {
            this.throwError(`File magics incorrect. Expecting 0x504A or 0x4A50, but got 0x${MAGICS.toString(16).padStart(4, "0")} ` + this.fileName);
        }
        if (MAGICS == 0x4A50) {
            this.endian = "big";
        }
        const V_MAJOR = br.uint8;
        const V_MINOR = br.uint8;
        this.HEADER_SIZE = br.uint8;
        this.LargeFile = br.bit1;
        this.Compressed = br.bit1;
        this.Crc32 = br.bit1;
        this.Encrypted = br.bit1;
        this.EncryptionExcluded = br.bit1;
        this.KeyStripped = br.bit1;
        br.bit1; // FLAG6
        br.bit1; // FLAG7
        br.uint8; // RESV_6 FLAG8-15
        br.uint8; // RESV_7 FLAG16-23
        this.VALUE_SIZE = br.uint64;
        this.STR_SIZE = br.uint64;
        this.DATA_SIZE = br.uint64;
        const V_NUMBER = parseFloat(`${V_MAJOR}.${V_MINOR}`);
        if (V_NUMBER > VERSION_NUMBER) {
            this.addError(`File was encoded in a more advanced version of this package which may cause issues. Package: ${VERSION_NUMBER} - File: ${V_NUMBER} ` + this.fileName);
        }
        if (this.LargeFile && (br.size > MAX_BUFFER || (this.STR_SIZE + this.VALUE_SIZE) > MAX_BUFFER)) {
            this.useFile = true;
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
    }
    ;
    /**
     * Sets up valueReader & strReader. Will decomp and decrypt as well.
     *
     * If a temp file is made, will have to delete after.
     */
    reinitializeState() {
        if (this.useFile) {
            if (this.fileReader != null) {
                this.fileReader.close();
                this.fileReader = null;
            }
            this.compReader = new BiReader(this.fileName, { enforceBigInt: this.enforceBigInt });
            this.compReader.endian = this.endian;
            this.compReader.open();
            this.compReader.goto(this.HEADER_SIZE);
            this.tempCreated = false;
            if (this.Encrypted) {
                // make comp file without header
                const compWriter = new BiWriter(this.fileName + ".comp", { enforceBigInt: this.enforceBigInt });
                compWriter.unrestrict();
                compWriter.endian = this.endian;
                compWriter.open();
                compWriter.overwrite(this.compReader.subarray(this.HEADER_SIZE, this.compReader.size - this.HEADER_SIZE), compWriter.offset, true);
                compWriter.trim();
                this.tempCreated = true;
                var finalSize = 0;
                if (this.Compressed) {
                    finalSize = Number(this.DATA_SIZE);
                }
                else {
                    finalSize = Number(this.VALUE_SIZE + this.STR_SIZE);
                }
                this.decrypt(compWriter, null, finalSize);
                compWriter.close();
                this.compReader = new BiReader(this.fileName + ".comp", { enforceBigInt: this.enforceBigInt });
                this.compReader.endian = this.endian;
                this.compReader.unrestrict();
                this.compReader.open();
            }
            if (this.Compressed) {
                // check if comp file was made
                if (this.tempCreated) {
                    // compReader should be just the data
                    const tempcompWriter = new BiWriter(this.fileName + ".comp.tmp", { enforceBigInt: this.enforceBigInt });
                    tempcompWriter.endian = this.endian;
                    tempcompWriter.open();
                    inflateFileSync(this.compReader, tempcompWriter);
                    this.compReader.writeMode(true);
                    this.compReader.gotoStart();
                    this.compReader.overwrite(tempcompWriter.subarray(0, tempcompWriter.offset), this.compReader.offset, true);
                    this.compReader.trim();
                    this.compReader.writeMode(false);
                    tempcompWriter.deleteFile();
                }
                else {
                    // split off header
                    const compWriter = new BiWriter(this.fileName + ".comp", { enforceBigInt: this.enforceBigInt });
                    compWriter.endian = this.endian;
                    compWriter.open();
                    compWriter.overwrite(this.compReader.subarray(this.HEADER_SIZE, this.compReader.size - this.HEADER_SIZE), compWriter.offset, true);
                    compWriter.trim();
                    compWriter.close();
                    const compReader = new BiReader(this.fileName + ".comp", { enforceBigInt: this.enforceBigInt });
                    compReader.endian = this.endian;
                    compReader.unrestrict();
                    const tempcompWriter = new BiWriter(this.fileName + ".comp.tmp", { enforceBigInt: this.enforceBigInt });
                    tempcompWriter.endian = this.endian;
                    tempcompWriter.open();
                    this.tempCreated = true;
                    inflateFileSync(compReader, tempcompWriter);
                    compReader.writeMode(true);
                    compReader.gotoStart();
                    compReader.overwrite(tempcompWriter.subarray(0, tempcompWriter.offset), compReader.offset, true);
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
                    const buffer = this.compReader.subarray(position, Math.min(CHUNK_SIZE, this.compReader.size - position));
                    if (buffer.length == 0)
                        break;
                    crc = CRC32(buffer, crc);
                    position += buffer.length;
                }
                this.CRC32Hash = crc >>> 0;
                if (this.CRC32Hash != this.CRC32OnFile) {
                    this.addError(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32OnFile} but got ${this.CRC32Hash}. ` + this.fileName);
                }
            }
            var totalSize = 0n;
            if (this.tempCreated) {
                totalSize = BigInt(this.compReader.size);
                this.compReader.open();
                this.valueReader = new BiReader(this.fileName + ".comp", { enforceBigInt: this.enforceBigInt });
                this.strReader = new BiReader(this.fileName + ".comp", { enforceBigInt: this.enforceBigInt });
                this.valueReader.fd = this.compReader.fd;
                this.valueReader.endian = this.compReader.endian;
                this.valueReader.size = this.compReader.size;
                this.valueReader.bitSize = this.compReader.bitSize;
                this.valueReader.growthIncrement = this.compReader.growthIncrement;
                this.strReader.fd = this.compReader.fd;
                this.strReader.endian = this.compReader.endian;
                this.strReader.size = this.compReader.size;
                this.strReader.bitSize = this.compReader.bitSize;
                this.strReader.growthIncrement = this.compReader.growthIncrement;
                this.strReader.offset = Number(this.VALUE_SIZE);
            }
            else {
                totalSize = BigInt(this.compReader.size - this.HEADER_SIZE);
                this.compReader.open();
                this.valueReader = new BiReader(this.fileName, { enforceBigInt: this.enforceBigInt });
                this.strReader = new BiReader(this.fileName, { enforceBigInt: this.enforceBigInt });
                this.valueReader.fd = this.compReader.fd;
                this.valueReader.endian = this.compReader.endian;
                this.valueReader.size = this.compReader.size;
                this.valueReader.bitSize = this.compReader.bitSize;
                this.valueReader.growthIncrement = this.compReader.growthIncrement;
                this.valueReader.offset = this.HEADER_SIZE;
                this.strReader.fd = this.compReader.fd;
                this.strReader.endian = this.compReader.endian;
                this.strReader.size = this.compReader.size;
                this.strReader.bitSize = this.compReader.bitSize;
                this.strReader.growthIncrement = this.compReader.growthIncrement;
                this.strReader.offset = this.HEADER_SIZE + Number(this.VALUE_SIZE);
            }
            if (this.VALUE_SIZE + this.STR_SIZE != totalSize) {
                this.addError(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${totalSize}. ` + this.fileName);
            }
        }
        else {
            if (this.buffer == null) {
                this.throwError(" Buffer not set. " + this.fileName);
            }
            this.fileReader = new BiReader(this.buffer, { enforceBigInt: this.enforceBigInt });
            this.fileReader.endian = this.endian;
            this.fileReader.goto(this.HEADER_SIZE);
            var decomBuffer = this.buffer.subarray(this.HEADER_SIZE, this.buffer.length);
            this.compReader = new BiReader(decomBuffer, { enforceBigInt: this.enforceBigInt });
            this.compReader.endian = this.endian;
            if (this.Encrypted) {
                var finalSize = Number(this.VALUE_SIZE + this.STR_SIZE);
                if (this.Compressed) {
                    finalSize = Number(this.DATA_SIZE);
                }
                decomBuffer = this.decrypt(null, decomBuffer, finalSize);
                this.compReader = new BiReader(decomBuffer, { enforceBigInt: this.enforceBigInt });
                this.compReader.endian = this.endian;
            }
            if (this.Compressed) {
                decomBuffer = inflateBuffer(this.compReader);
                this.compReader = new BiReader(decomBuffer, { enforceBigInt: this.enforceBigInt });
                this.compReader.endian = this.endian;
            }
            if (this.Crc32) {
                const data = this.compReader.data;
                this.CRC32Hash = CRC32(data, 0) >>> 0;
                if (this.CRC32Hash != this.CRC32OnFile) {
                    this.addError(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32OnFile} but got ${this.CRC32Hash}. ` + this.fileName);
                }
            }
            if (this.VALUE_SIZE + this.STR_SIZE != BigInt(this.compReader.size)) {
                this.addError(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${this.compReader.size}. ` + this.fileName);
            }
            this.valueReader = new BiReader(this.compReader.extract(Number(this.VALUE_SIZE), true));
            this.valueReader.endian = this.endian;
            this.strReader = new BiReader(this.compReader.extract(Number(this.STR_SIZE), true));
            this.strReader.endian = this.endian;
        }
    }
    ;
    setBuffer(buffer) {
        this.buffer = ensureBuffer(buffer);
        this.fileReader = new BiReader(this.buffer, { enforceBigInt: this.enforceBigInt });
        this.testHeader(this.fileReader);
        this.fileReader.close();
        this.fileReader = null;
    }
    ;
    createStringList() {
        if (this.strReader == null) {
            this.throwError(" string reader not set. " + this.fileName);
        }
        DECODE: while (true) {
            const headByte = this.strReader.ubyte;
            let object;
            if ((headByte >= exports.JPType.ARRAY_0 && headByte <= exports.JPType.ARRAY_15) || // arrays
                (headByte >= exports.JPType.ARRAY8 && headByte <= exports.JPType.ARRAY32)) {
                var size = 0;
                if (headByte <= exports.JPType.ARRAY_15) {
                    size = headByte - exports.JPType.ARRAY_0;
                }
                else if (headByte === exports.JPType.ARRAY8) {
                    size = this.strReader.ubyte;
                }
                else if (headByte === exports.JPType.ARRAY16) {
                    size = this.strReader.uint16;
                }
                else if (headByte === exports.JPType.ARRAY32) {
                    size = this.strReader.uint32;
                }
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if ((headByte >= exports.JPType.STR_0 && headByte <= exports.JPType.STR_15) || // strings
                (headByte >= exports.JPType.STR8 && headByte <= exports.JPType.STR32)) {
                var size = 0;
                if (headByte <= exports.JPType.STR_15) {
                    size = headByte - exports.JPType.STR_0;
                }
                else if (headByte === exports.JPType.STR8) {
                    size = this.strReader.ubyte;
                }
                else if (headByte === exports.JPType.STR16) {
                    size = this.strReader.uint16;
                }
                else if (headByte === exports.JPType.STR32) {
                    size = this.strReader.uint32;
                }
                object = this.strReader.string({ length: size });
            }
            else {
                this.throwError(`Invalid data in string area. 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }
            const stack = this.stack;
            while (stack.length > 0) {
                // arrays
                const state = stack.top();
                if (state.type === STATE_ARRAY$1) {
                    state.array[state.position] = object;
                    state.position++;
                    if (state.position === state.size) {
                        object = state.array;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else {
                    this.throwError(' Should only have an array in the string data, found type ' + state.type + " in file " + this.fileName);
                }
            }
            return object;
        }
    }
    ;
    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     *
     * NOTE: This function is for extention use, not direct use. Use `decode` instead.
     *
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    doDecode(bufferOrReader) {
        var reader = bufferOrReader;
        if (reader instanceof Buffer) {
            reader = new BiReader(reader, { enforceBigInt: this.enforceBigInt });
            reader.endian = this.endian;
        }
        if (!(reader instanceof BiReader) || reader == null) {
            this.throwError(" Value reader not set. " + this.fileName);
        }
        if (this.strReader == null) {
            this.throwError(" String reader not set. " + this.fileName);
        }
        reader = reader;
        let object;
        DECODE: while (true) {
            const headByte = reader.ubyte;
            if (headByte < exports.JPType.OBJECT_0) {
                // positive fixint 0x00 - 0x7f
                object = headByte;
            }
            else if (headByte < exports.JPType.ARRAY_0) {
                // fix object 0x80 - 0x8f
                const size = headByte - 0x80;
                if (size !== 0) {
                    this.pushObjectState(size);
                    continue DECODE;
                }
                else {
                    object = {};
                }
            }
            else if (headByte < exports.JPType.KEY_0) {
                //fixarray
                const size = headByte - 0x90;
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if (headByte < exports.JPType.STR_0) {
                //fixkey (only used in stripping)
                const index = headByte - 0xA0;
                if (!this.keysArray[index]) {
                    this.addError(`Did not find key value for index ` + index + " in file " + this.fileName);
                }
                object = this.keysArray[index];
            }
            else if (headByte < exports.JPType.NULL) {
                //fixstr
                const index = headByte - 0xB0;
                if (this.stringsList[index] === undefined) {
                    this.addError(`Did not find string value for index ` + index + " in file " + this.fileName);
                }
                object = this.stringsList[index];
            }
            else if (headByte == exports.JPType.NULL) {
                object = null;
            }
            else if (headByte == exports.JPType.UNDEFINED) {
                object = undefined;
                this.validJSON = false;
            }
            else if (headByte == exports.JPType.BOOL_FALSE) {
                object = false;
            }
            else if (headByte == exports.JPType.BOOL_TRUE) {
                object = true;
            }
            else if (headByte == exports.JPType.FINISHED ||
                headByte == exports.JPType.UNUSED_C6) {
                return object;
            }
            else if (headByte == exports.JPType.LIST_END) {
                const state = this.stack.top();
                if (state.type != undefined) {
                    if (state.type == STATE_ARRAY$1) {
                        object = state.array;
                    }
                    else if (state.type == STATE_OBJECT_KEY$1 || state.type == STATE_OBJECT_VALUE$1) {
                        object = state.object;
                    }
                    else if (state.type == STATE_MAP_KEY$1 || state.type == STATE_MAP_VALUE$1) {
                        object = state.map;
                    }
                    this.stack.release(state);
                }
                return object;
            }
            else if (headByte <= exports.JPType.OBJECT32) {
                // non-fix object
                var size = 0;
                if (headByte === exports.JPType.OBJECT8) {
                    size = reader.ubyte;
                }
                else if (headByte === exports.JPType.OBJECT16) {
                    size = reader.uint16;
                }
                else if (headByte === exports.JPType.OBJECT32) {
                    size = reader.uint32;
                }
                if (size !== 0) {
                    this.pushObjectState(size);
                    continue DECODE;
                }
                else {
                    object = {};
                }
            }
            else if (headByte === exports.JPType.FLOAT32) {
                object = reader.float;
            }
            else if (headByte === exports.JPType.FLOAT64) {
                object = reader.doublefloat;
            }
            else if (headByte === exports.JPType.UINT_8) {
                object = reader.uint8;
            }
            else if (headByte === exports.JPType.UINT_16) {
                object = reader.uint16;
            }
            else if (headByte === exports.JPType.UINT_32) {
                object = reader.uint32;
            }
            else if (headByte === exports.JPType.UINT_64) {
                object = reader.uint64;
                if (this.enforceBigInt) {
                    object = BigInt(object);
                }
                if (typeof object === "bigint") {
                    this.validJSON = false;
                }
            }
            else if (headByte === exports.JPType.INT_8) {
                object = reader.int8;
            }
            else if (headByte === exports.JPType.INT_16) {
                object = reader.int16;
            }
            else if (headByte === exports.JPType.INT_32) {
                object = reader.int32;
            }
            else if (headByte === exports.JPType.INT_64) {
                object = reader.int64;
                if (this.enforceBigInt) {
                    object = BigInt(object);
                }
                if (typeof object === "bigint") {
                    this.validJSON = false;
                }
            }
            else if (headByte <= exports.JPType.KEY32) {
                // nonfix key
                var index = 0;
                if (headByte === exports.JPType.KEY8) {
                    index = reader.ubyte;
                }
                else if (headByte === exports.JPType.KEY16) {
                    index = reader.uint16;
                }
                else if (headByte === exports.JPType.KEY32) {
                    index = reader.uint32;
                }
                if (!this.keysArray[index]) {
                    this.addError(`Did not find key value for index ` + index + " in file " + this.fileName);
                }
                object = this.keysArray[index];
            }
            else if (headByte <= exports.JPType.STR32) {
                // non-fix string
                var index = 0;
                if (headByte === exports.JPType.STR8) {
                    index = reader.ubyte;
                }
                else if (headByte === exports.JPType.STR16) {
                    index = reader.uint16;
                }
                else if (headByte === exports.JPType.STR32) {
                    index = reader.uint32;
                }
                if (this.stringsList[index] === undefined) {
                    this.addError(`Did not find string value for index ` + index + " in file " + this.fileName);
                }
                object = this.stringsList[index];
            }
            else if (headByte <= exports.JPType.ARRAY32) {
                // non-fix array
                var size = 0;
                if (headByte === exports.JPType.ARRAY8) {
                    size = reader.ubyte;
                }
                else if (headByte === exports.JPType.ARRAY16) {
                    size = reader.uint16;
                }
                else if (headByte === exports.JPType.ARRAY32) {
                    size = reader.uint32;
                }
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if (headByte <= exports.JPType.EXT32) {
                this.hasExtensions = true;
                var size = 0;
                if (headByte === exports.JPType.EXT8) {
                    size = reader.ubyte;
                }
                else if (headByte === exports.JPType.EXT16) {
                    size = reader.uint16;
                }
                else if (headByte === exports.JPType.EXT32) {
                    size = reader.uint32;
                }
                const type = reader.ubyte;
                if (type == exports.JPExtType.Maps) {
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushMapState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Map();
                    }
                }
                else if (type == exports.JPExtType.Sets) {
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushSetState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Set();
                    }
                }
                else {
                    object = this.decodeExtension(reader, size, type);
                }
            }
            else if (headByte > exports.JPType.EXT32) {
                // negative fixint
                object = headByte - 0x100;
            }
            else {
                this.throwError(`Outside of index error 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }
            const stack = this.stack;
            while (stack.length > 0) {
                // arrays and maps
                const state = stack.top();
                if (state.type === STATE_ARRAY$1) {
                    state.array[state.position] = object;
                    state.position++;
                    if (state.position === state.size) {
                        object = state.array;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_SET$1) {
                    state.set.add(object);
                    state.position++;
                    if (state.position === state.size) {
                        object = state.set;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_OBJECT_KEY$1) {
                    if (object === "__proto__") {
                        this.throwError(" The key __proto__ is not allowed " + this.fileName);
                    }
                    state.key = this.mapKeyConverter(object);
                    state.type = STATE_OBJECT_VALUE$1;
                    continue DECODE;
                }
                else if (state.type === STATE_OBJECT_VALUE$1) {
                    state.object[state.key] = object;
                    state.readCount++;
                    if (state.readCount === state.size) {
                        object = state.object;
                        stack.release(state);
                    }
                    else {
                        state.key = null;
                        state.type = STATE_OBJECT_KEY$1;
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_MAP_KEY$1) {
                    if (object === "__proto__") {
                        this.throwError(" The key __proto__ is not allowed " + this.fileName);
                    }
                    state.key = this.mapKeyConverter(object);
                    state.type = STATE_MAP_VALUE$1;
                    continue DECODE;
                }
                else if (state.type === STATE_MAP_VALUE$1) {
                    // it must be `state.type === State.MAP_VALUE` here
                    state.map.set(state.key, object);
                    state.readCount++;
                    if (state.readCount === state.size) {
                        object = state.map;
                        stack.release(state);
                    }
                    else {
                        state.key = null;
                        state.type = STATE_MAP_KEY$1;
                        continue DECODE;
                    }
                }
            }
            return object;
        }
    }
    ;
    pushMapState(size) {
        this.stack.pushMapState(size);
    }
    ;
    pushObjectState(size) {
        this.stack.pushObjectState(size);
    }
    ;
    pushArrayState(size) {
        this.stack.pushArrayState(size);
    }
    ;
    pushSetState(size) {
        this.stack.pushSetState(size);
    }
    ;
    readString(headByte) {
        if (this.valueReader == null) {
            this.throwError(" Value reader not set. " + this.fileName);
        }
        var value = "";
        if ((headByte >= exports.JPType.STR_0 && headByte <= exports.JPType.STR_15) || // strings
            (headByte >= exports.JPType.STR8 && headByte <= exports.JPType.STR32)) {
            var index = 0;
            if (headByte <= exports.JPType.STR_15) {
                index = headByte - exports.JPType.STR_0;
            }
            else if (headByte === exports.JPType.STR8) {
                index = this.valueReader.ubyte;
            }
            else if (headByte === exports.JPType.STR16) {
                index = this.valueReader.uint16;
            }
            else if (headByte === exports.JPType.STR32) {
                index = this.valueReader.uint32;
            }
            if (this.stringsList[index] === undefined) {
                this.addError(`Did not find string value for index ` + index + " in file " + this.fileName);
            }
            else {
                value = this.stringsList[index];
            }
        }
        return value;
    }
    ;
    decodeExtension(valueReader, size, extType) {
        let retValue, data, holder;
        switch (extType) {
            case exports.JPExtType.Symbol:
                this.validJSON = false;
                // bool and string
                const global = valueReader.ubyte == exports.JPType.BOOL_TRUE ? true : false;
                var headByte = valueReader.ubyte;
                const key = this.readString(headByte);
                retValue = global ? Symbol.for(key) : Symbol(key);
                this.symbolList.push(retValue);
                break;
            case exports.JPExtType.RegEx:
                this.validJSON = false;
                // two strings
                const source = this.readString(valueReader.ubyte);
                const flags = this.readString(valueReader.ubyte);
                retValue = new RegExp(source, flags);
                break;
            case exports.JPExtType.Maps:
                this.validJSON = false;
                // handled before
                break;
            case exports.JPExtType.Sets:
                this.validJSON = false;
                // handled before
                break;
            case exports.JPExtType.BigUint64Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new BigUint64Array(holder.buffer);
                break;
            case exports.JPExtType.BigInt64Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new BigInt64Array(holder.buffer);
                break;
            case exports.JPExtType.Float64Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Float64Array(holder.buffer);
                break;
            case exports.JPExtType.Float32Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Float32Array(holder.buffer);
                break;
            case exports.JPExtType.Float16Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                // @ts-ignore
                if (typeof Float16Array !== 'undefined') {
                    // @ts-ignore
                    retValue = new Float16Array(holder.buffer);
                }
                break;
            case exports.JPExtType.Int32Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int32Array(holder.buffer);
                break;
            case exports.JPExtType.Uint32Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint32Array(holder.buffer);
                break;
            case exports.JPExtType.Uint16Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint16Array(holder.buffer);
                break;
            case exports.JPExtType.Int16Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int16Array(holder.buffer);
                break;
            case exports.JPExtType.Int8Array:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int8Array(holder.buffer);
                break;
            case exports.JPExtType.Uint8Array:
                data = valueReader.extract(size, true);
                retValue = new Uint8Array(data);
                break;
            case exports.JPExtType.Uint8ClampedArray:
                data = valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint8ClampedArray(holder.buffer);
                break;
            case exports.JPExtType.Buffer:
                retValue = valueReader.extract(size, true);
                retValue = Buffer.from(retValue);
                break;
            case exports.JPExtType.Date:
                data = valueReader.extract(size, true);
                const br = new BiReader(data, { enforceBigInt: this.enforceBigInt });
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
                        this.throwError(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${br.size} in file ` + this.fileName);
                }
                break;
        }
        if (retValue == undefined) {
            const data = valueReader.extract(size, true);
            const br = new BiReader(data, { enforceBigInt: this.enforceBigInt });
            br.endian = this.endian;
            retValue = this.extensionCodec.decode(br, this, extType, this.context);
        }
        return retValue;
    }
    ;
    ////////////////////////
    // #region FINALIZE
    ////////////////////////
    decrypt(br, buffer, finalSize) {
        const cypter = new Crypt(this.encryptionKey);
        if (!this.useFile) {
            if (buffer == null) {
                this.throwError(" Buffer to decrypt not set. " + this.fileName);
            }
            const decrypted = cypter.decrypt(buffer);
            if (decrypted.length != finalSize) {
                this.addError(`Decrypted buffer size of ${decrypted.length} wasn expected size of ${finalSize} in file ` + this.fileName);
            }
            return decrypted;
        }
        else {
            const CHUNK_SIZE = 16;
            br.open();
            br.gotoStart();
            var buff = Buffer.alloc(0);
            var data;
            let bytesToProcess = br.size;
            let bytesStart = 0;
            let bytesRead = 0;
            let amount = Math.ceil(br.size / CHUNK_SIZE);
            for (let index = 0; index < amount; index++) {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                buff = br.subarray(bytesStart, bytesRead);
                if (index == (amount - 1)) {
                    data = cypter.decrypt_block(buff, true);
                }
                else {
                    data = cypter.decrypt_block(buff);
                }
                if (data.length != 0) {
                    br.overwrite(data, null, true);
                }
                bytesStart += buff.length;
                bytesToProcess -= buff.length;
            }
            data = cypter.decrypt_final();
            if (data.length != 0) {
                br.overwrite(data, null, true);
            }
            br.trim();
            if (br.size != finalSize) {
                this.addError(`Decrypted buffer size of ${br.size} was expected size of ${finalSize} in file ` + this.fileName);
            }
            return Buffer.alloc(0);
        }
    }
    ;
}

/**
 * Create with `EncoderOptions`
 */
class JPEncode extends JPBase {
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MAJOR() {
        return VERSION_MAJOR;
    }
    ;
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MINOR() {
        return VERSION_MINOR;
    }
    ;
    /**
     * Set up with basic options
     *
     * @param {EncoderOptions?} encodeOptions - options for encoding
     */
    constructor(encodeOptions) {
        super();
        this.stringList = new stringList();
        this.keyList = new stringList();
        this.depth = 0;
        ////////////////////////
        // #region CONSTANTS 
        ////////////////////////
        /**
         * JP or PJ
         */
        this.MAGIC = 0x504A;
        /**
         * Endianness. Defaults to ``little``
         */
        this.endian = "little";
        this.CRC32Hash = 0;
        this.extensionCodec = encodeOptions?.extensionCodec ?? JPExtensionCodec.defaultCodec;
        this.context = encodeOptions?.context; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined
        this.endian = encodeOptions?.endian ? encodeOptions.endian : "little";
        this.Encrypted = encodeOptions?.encrypt ? 1 : 0;
        this.EncryptionExcluded = encodeOptions?.stripEncryptKey ? 1 : 0;
        this.encryptionKey = encodeOptions?.encryptionKey ? encodeOptions.encryptionKey : 0;
        this.Compressed = encodeOptions?.compress ? 1 : 0;
        this.KeyStripped = encodeOptions?.stripKeys ? 1 : 0;
        this.Crc32 = encodeOptions?.CRC32 ? 1 : 0;
        this.growthIncrement = encodeOptions?.growthIncrement ? encodeOptions.growthIncrement : GROWTHINCREMENT_DEFAULT;
    }
    ;
    clone() {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // @ts-ignore
        const clone = new JPEncode({
            extensionCodec: this.extensionCodec,
            context: this.context,
            endian: this.endian,
            encrypt: this.Encrypted,
            stripEncryptKey: this.EncryptionExcluded,
            encryptionKey: this.encryptionKey,
            compress: this.Compressed,
            stripKeys: this.KeyStripped,
            CRC32: this.Crc32,
            growthIncrement: this.growthIncrement,
        });
        clone.fileName = this.fileName;
        clone.useFile = this.useFile;
        clone.valueWriter = this.valueWriter;
        clone.strWriter = this.strWriter;
        clone.keysArray = this.keysArray;
        clone.compWriter = this.compWriter;
        return clone;
    }
    ;
    /**
     * Basic encode, will run options that were set in constructor.
     *
     * @param {any} object - Data to encode
     * @param {string} filePath - Optional file path to write the file to directly
     * @returns {Buffer}
     */
    encode(object, filePath) {
        if (this.entered) {
            const instance = this.clone();
            return instance.encode(object, filePath);
        }
        this.fileName = filePath ? filePath : "";
        if (this.fileName != "") {
            this.useFile = true;
        }
        try {
            this.entered = true;
            this.reinitializeState();
            if (this.valueWriter == null || this.strWriter == null) {
                this.throwError(" Didn't create writers. " + this.fileName);
            }
            this.doEncode(this.valueWriter, object, 1);
            this.valueWriter.ubyte = exports.JPType.FINISHED;
            this.valueWriter.trim();
            this.valueWriter.commit();
            this.VALUE_SIZE = this.valueWriter.size;
            this.writeStringsData();
            this.strWriter.ubyte = exports.JPType.FINISHED;
            this.strWriter.trim();
            this.strWriter.commit();
            this.STR_SIZE = this.strWriter.size;
            if (this.KeyStripped) {
                this.keysArray = this.keyList.getValues();
            }
            this.finalizeBuffers();
            this.headerBuffer = this.buildHeader();
            if (this.compWriter == null) {
                this.throwError(" Didn't create writer. " + this.fileName);
            }
            const newOff = this.compWriter.offset + this.headerBuffer.length;
            this.compWriter.gotoStart();
            this.compWriter.unshift(this.headerBuffer, true);
            this.compWriter.goto(newOff);
            this.compWriter.trim();
            this.compWriter.commit();
            const compBuffer = this.compWriter.data;
            this.compWriter.close();
            return compBuffer;
        }
        catch (err) {
            console.error(err);
            return Buffer.alloc(0);
        }
        finally {
            this.entered = false;
        }
    }
    ;
    reinitializeState() {
        if (this.useFile) {
            this.valueWriter = new BiWriter(this.fileName + ".values", { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
            this.valueWriter.open();
            this.valueWriter.endian = this.endian;
            this.strWriter = new BiWriter(this.fileName + ".strings", { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
            this.strWriter.open();
            this.strWriter.endian = this.endian;
        }
        else {
            this.valueWriter = new BiWriter(Buffer.alloc(this.growthIncrement), { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
            this.valueWriter.endian = this.endian;
            this.strWriter = new BiWriter(Buffer.alloc(this.growthIncrement), { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
            this.strWriter.endian = this.endian;
        }
    }
    ;
    doEncode(valueWriter, object, depth) {
        this.depth = depth;
        if (object === null) {
            return this.encodeNull(valueWriter);
        }
        else if (object === undefined) {
            return this.encodeUndefined(valueWriter);
        }
        else if (typeof object === "boolean") {
            return this.encodeBoolean(valueWriter, object);
        }
        else if (typeof object === "number") {
            return this.encodeNumber(valueWriter, object);
        }
        else if (typeof object === "string") {
            return this.encodeString(valueWriter, object, false);
        }
        else if (typeof object === "bigint") {
            return this.encodeBigInt64(valueWriter, object);
        }
        else if (typeof object === "symbol") {
            return this.encodeSymbol(valueWriter, object); // EXT
        }
        else {
            // if (typeof object === "object")
            const ext = this.extensionCodec.tryToEncode(object, this, this.context);
            if (ext != null) {
                return this.encodeExtension(valueWriter, ext); //EXT
            }
            else if (Array.isArray(object)) {
                return this.encodeArray(valueWriter, object, this.depth);
            }
            else if (object instanceof Map) {
                return this.encodeMap(valueWriter, object, this.depth); // EXT
            }
            else if (object instanceof Set) {
                return this.encodeSet(valueWriter, object, this.depth); // EXT
            }
            else if (object instanceof RegExp) {
                return this.encodeRegEx(valueWriter, object); // EXT
            }
            else if (ArrayBuffer.isView(object) || object instanceof Buffer) {
                return this.encodeBinary(valueWriter, object); // EXT
            }
            else if (object instanceof Date) {
                return this.encodeDate(valueWriter, object); // EXT
            }
            else if (typeof object === "object") {
                return this.encodeObject(valueWriter, object, this.depth);
            }
            else {
                // function and other special object come here unless extensionCodec handles them.
                this.throwError(`Unrecognized object: ${Object.prototype.toString.apply(object)} ` + this.fileName);
            }
        }
    }
    ;
    ////////////////////////
    // #region STANDARD
    ////////////////////////
    /**
     * Writes an `Object` to the buffer as `Record<string, unknown>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeObject(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        var length = 1;
        const keys = Object.keys(object);
        const size = keys.length;
        if (size < 16) {
            // fixmap
            valueWriter.ubyte = exports.JPType.OBJECT_0 + size;
        }
        else if (size < 0x100) {
            // map 8
            valueWriter.ubyte = exports.JPType.OBJECT8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            // map 16
            valueWriter.ubyte = exports.JPType.OBJECT16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            // map 32
            valueWriter.ubyte = exports.JPType.OBJECT32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            this.throwError(`Too large map object: ${size} in file ` + this.fileName);
        }
        for (const key of keys) {
            const value = object[key];
            length += this.encodeString(valueWriter, key, true);
            length += this.doEncode(valueWriter, value, depth + 1);
        }
        return length;
    }
    ;
    /**
     * Writes an `Array` to the buffer as `Array<unknown>`
     *
     * @param valueWriter - Writer
     * @param array - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeArray(valueWriter, array, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        var length = 1;
        const size = array.length;
        if (size < 16) {
            // fixarray
            valueWriter.ubyte = exports.JPType.ARRAY_0 + size;
        }
        else if (size < 0x100) {
            // uint8
            valueWriter.ubyte = exports.JPType.ARRAY8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            // array 16
            valueWriter.ubyte = exports.JPType.ARRAY16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            // array 32
            valueWriter.ubyte = exports.JPType.ARRAY32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            this.throwError(`Too large array: ${size} in file ` + this.fileName);
        }
        for (const item of array) {
            length += this.doEncode(valueWriter, item, depth + 1);
        }
        return length;
    }
    ;
    /**
     * Writes a `string` to the buffer's string section.
     *
     * @param valueWriter - Writer
     * @param string - Data to encode
     * @param isKey If the string is used a an Object key. Only used when `stripKeys` is enabled.
     * @returns The `number` of bytes written
     */
    encodeString(valueWriter, string, isKey) {
        if (isKey == undefined) {
            isKey = false;
        }
        var length = 1;
        if (isKey && this.KeyStripped) {
            const index = this.keyList.add(string);
            if (index < 16) {
                valueWriter.ubyte = exports.JPType.KEY_0 + index;
            }
            else if (index < 0x100) {
                // uint8
                valueWriter.ubyte = exports.JPType.KEY8;
                valueWriter.ubyte = index;
                length++;
            }
            else if (index < 0x10000) {
                // unit16
                valueWriter.ubyte = exports.JPType.KEY16;
                valueWriter.ushort = index;
                length += 2;
            }
            else if (index < 0x100000000) {
                // unit32
                valueWriter.ubyte = exports.JPType.KEY32;
                valueWriter.uint32 = index;
                length += 4;
            }
            else {
                this.throwError(`String index too long: ${index} in file ` + this.fileName);
            }
        }
        else {
            const index = this.stringList.add(string);
            if (index < 16) {
                valueWriter.ubyte = exports.JPType.STR_0 + index;
            }
            else if (index < 0x100) {
                // uint8
                valueWriter.ubyte = exports.JPType.STR8;
                valueWriter.ubyte = index;
                length++;
            }
            else if (index < 0x10000) {
                // unit16
                valueWriter.ubyte = exports.JPType.STR16;
                valueWriter.ushort = index;
                length += 2;
            }
            else if (index < 0x100000000) {
                // unit32
                valueWriter.ubyte = exports.JPType.STR32;
                valueWriter.uint32 = index;
                length += 4;
            }
            else {
                this.throwError(`String index too long: ${index} in file ` + this.fileName);
            }
        }
        return length;
    }
    ;
    /**
     * Writes a `null` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeNull(valueWriter) {
        valueWriter.ubyte = exports.JPType.NULL;
        return 1;
    }
    ;
    /**
     * Writes an `undefined` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeUndefined(valueWriter) {
        valueWriter.ubyte = exports.JPType.UNDEFINED;
        return 1;
    }
    ;
    /**
     * Writes a `boolean` true or false to the buffer
     *
     * @param valueWriter - Writer
     * @param object - `true` or `false`
     * @returns The `number` of bytes written
     */
    encodeBoolean(valueWriter, object) {
        if (object === false) {
            valueWriter.ubyte = exports.JPType.BOOL_FALSE;
        }
        else {
            valueWriter.ubyte = exports.JPType.BOOL_TRUE;
        }
        return 1;
    }
    ;
    /**
     * Writes an "finished" byte to the buffer. End the loop when hit if not finished otherwise.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeFinished(valueWriter) {
        valueWriter.ubyte = exports.JPType.FINISHED;
        return 1;
    }
    ;
    /**
     * Writes a "list end" byte to the buffer, useful when pulling loose data and don't want to break the whole loop.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    encodeListEnd(valueWriter) {
        valueWriter.ubyte = exports.JPType.LIST_END;
        return 1;
    }
    ;
    /**
     * Writes a `number` to the buffer . Computes the right byte size base on value.
     *
     * Notes: Use `encodeBigInt64` for `bigint` types.
     *
     * @param valueWriter - Writer
     * @param number - Data to encode
     * @returns The `number` of bytes written
     */
    encodeNumber(valueWriter, number) {
        var length = 1;
        if (Number.isSafeInteger(number)) {
            if (number >= 0) {
                if (number < 0x80) {
                    // positive fixint
                    valueWriter.ubyte = number;
                }
                else if (number < 0x100) {
                    // uint 8
                    valueWriter.ubyte = exports.JPType.UINT_8;
                    valueWriter.ubyte = number;
                    length++;
                }
                else if (number < 0x10000) {
                    // uint 16
                    valueWriter.ubyte = exports.JPType.UINT_16;
                    valueWriter.ushort = number;
                    length += 2;
                }
                else if (number < 0x100000000) {
                    // uint 32
                    valueWriter.ubyte = exports.JPType.UINT_32;
                    valueWriter.uint32 = number;
                    length += 4;
                }
                else {
                    // uint 64
                    valueWriter.ubyte = exports.JPType.UINT_64;
                    valueWriter.uint64 = number;
                    length += 8;
                }
            }
            else {
                if (number >= -32) {
                    // negative fixint
                    valueWriter.byte = number;
                }
                else if (number >= -128) {
                    // int 8
                    valueWriter.ubyte = exports.JPType.INT_8;
                    valueWriter.byte = number;
                    length++;
                }
                else if (number >= -32768) {
                    // int 16
                    valueWriter.ubyte = exports.JPType.INT_16;
                    valueWriter.int16 = number;
                    length += 2;
                }
                else if (number >= -2147483648) {
                    // int 32
                    valueWriter.ubyte = exports.JPType.INT_32;
                    valueWriter.int32 = number;
                    length += 4;
                }
                else {
                    // int 64
                    valueWriter.ubyte = exports.JPType.INT_64;
                    valueWriter.int64 = number;
                    length += 8;
                }
            }
            return length;
        }
        else {
            return this.encodeNumberAsFloat(valueWriter, number);
        }
    }
    ;
    /**
     * Writes a `bigint` to the buffer. Always written as a 64 bit value.
     *
     * @param valueWriter - Writer
     * @param bigint - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBigInt64(valueWriter, bigint) {
        var length = 0;
        if (bigint >= BigInt(0)) {
            // uint 64
            valueWriter.ubyte = exports.JPType.UINT_64;
            length++;
            valueWriter.uint64 = bigint;
            length += 8;
        }
        else {
            // int 64
            valueWriter.ubyte = exports.JPType.INT_64;
            length++;
            valueWriter.int64 = bigint;
            length += 8;
        }
        return length;
    }
    ;
    encodeStringHeader(byteLength) {
        var length = 1;
        if (this.strWriter == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }
        if (byteLength < 16) {
            // fixstr
            this.strWriter.ubyte = exports.JPType.STR_0 + byteLength;
        }
        else if (byteLength < 0x100) {
            // str 8
            this.strWriter.ubyte = exports.JPType.STR8;
            this.strWriter.ubyte = byteLength;
            length++;
        }
        else if (byteLength < 0x10000) {
            // str 16
            this.strWriter.ubyte = exports.JPType.STR16;
            this.strWriter.uint16 = byteLength;
            length += 2;
        }
        else if (byteLength < 0x100000000) {
            // str 32
            this.strWriter.ubyte = exports.JPType.STR32;
            this.strWriter.uint32 = byteLength;
            length += 4;
        }
        else {
            this.throwError(`Too long string: ${byteLength} bytes in UTF-8 in file ` + this.fileName);
        }
        return length;
    }
    ;
    writeString(object) {
        if (this.strWriter == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }
        const encoder = new TextEncoder();
        const encodedString = encoder.encode(object);
        const byteLength = encodedString.length;
        var length = this.encodeStringHeader(byteLength);
        this.strWriter.string(object, { length: byteLength });
        return length + byteLength;
    }
    ;
    writeStringsData() {
        const array = this.stringList.getValues();
        const size = array.length;
        if (this.strWriter == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }
        if (size < 16) {
            // fixarray
            this.strWriter.ubyte = exports.JPType.ARRAY_0 + size;
        }
        else if (size < 0x100) {
            // uint8
            this.strWriter.ubyte = exports.JPType.ARRAY8;
            this.strWriter.ubyte = size;
        }
        else if (size < 0x10000) {
            // array 16
            this.strWriter.ubyte = exports.JPType.ARRAY16;
            this.strWriter.ushort = size;
        }
        else if (size < 0x100000000) {
            // array 32
            this.strWriter.ubyte = exports.JPType.ARRAY32;
            this.strWriter.uint32 = size;
        }
        else {
            this.throwError(`String array too large: ${size} in file ` + this.fileName);
        }
        for (let i = 0; i < size; i++) {
            const el = array[i];
            this.writeString(el);
        }
    }
    ;
    encodeNumberAsFloat(valueWriter, object) {
        var length = 1;
        if (isFloat32Safe(object)) {
            // float 32
            valueWriter.ubyte = exports.JPType.FLOAT32;
            valueWriter.float = object;
            length += 4;
        }
        else {
            // float 64
            valueWriter.ubyte = exports.JPType.FLOAT64;
            valueWriter.dfloat = object;
            length += 8;
        }
        return length;
    }
    ;
    ////////////////////
    //  #region EXTS
    ////////////////////
    encodeExtension(valueWriter, ext) {
        const size = ext.data.length;
        var length = size;
        if (size < 0x100) {
            // ext 8
            valueWriter.ubyte = exports.JPType.EXT8;
            valueWriter.ubyte = size;
            length += 2;
        }
        else if (size < 0x10000) {
            // ext 16
            valueWriter.ubyte = exports.JPType.EXT16;
            valueWriter.ushort = size;
            length += 3;
        }
        else if (size < 0x100000000) {
            // ext 32
            valueWriter.ubyte = exports.JPType.EXT32;
            valueWriter.uint32 = size;
            length += 5;
        }
        else {
            this.throwError(`Too large extension object: ${size} in file ` + this.fileName);
        }
        valueWriter.ubyte = ext.type;
        length++;
        valueWriter.overwrite(ext.data, valueWriter.offset, true);
        return length;
    }
    ;
    /**
     * Writes a `Map` to the buffer as `Map<key, value>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeMap(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        // Note: length here is the array size of Map, not the buffer size
        var length = 1;
        const keys = [...object.keys()];
        const size = object.size;
        if (size < 0x100) {
            valueWriter.ubyte = exports.JPType.EXT8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            valueWriter.ubyte = exports.JPType.EXT16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            valueWriter.ubyte = exports.JPType.EXT32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            this.throwError(`Too large Set length: ${size} in file ` + this.fileName);
        }
        this.valueWriter.ubyte = exports.JPExtType.Maps;
        length++;
        for (const key of keys) {
            const value = object.get(key);
            length += this.doEncode(valueWriter, key, depth + 1); // keys can have any type here
            //this.valueWriter.ubyte = JPType.LIST_END; length++;
            length += this.doEncode(valueWriter, value, depth + 1);
            //this.valueWriter.ubyte = JPType.LIST_END; length++;
        }
        return length;
    }
    ;
    /**
     * Writes a `Set` to the buffer as `Set<type>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    encodeSet(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        // Note: length here is the array size of Set, not the buffer size
        var length = 1;
        const size = object.size;
        if (size < 0x100) {
            valueWriter.ubyte = exports.JPType.EXT8;
            valueWriter.ubyte = size;
            length++;
        }
        else if (size < 0x10000) {
            valueWriter.ubyte = exports.JPType.EXT16;
            valueWriter.ushort = size;
            length += 2;
        }
        else if (size < 0x100000000) {
            valueWriter.ubyte = exports.JPType.EXT32;
            valueWriter.uint32 = size;
            length += 4;
        }
        else {
            this.throwError(`Too large Set length: ${size} in file ` + this.fileName);
        }
        this.valueWriter.ubyte = exports.JPExtType.Sets;
        for (const item of object) {
            length += this.doEncode(valueWriter, item, depth + 1);
            // this.valueWriter.ubyte = JPType.LIST_END; length++;
        }
        return length;
    }
    ;
    /**
     * Writes a `symbol` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeSymbol(valueWriter, object) {
        const extBuffer = new BiWriter(Buffer.alloc(512), { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
        const keyCheck = Symbol.keyFor(object);
        const global = !!keyCheck;
        var key = keyCheck ?? object.description;
        key = key ?? "";
        var length = 0;
        length += this.encodeBoolean(extBuffer, global);
        length += this.encodeString(extBuffer, key, false);
        extBuffer.trim();
        if (length < 0x100) {
            valueWriter.ubyte = exports.JPType.EXT8;
            valueWriter.ubyte = length;
        }
        else if (length < 0x10000) {
            valueWriter.ubyte = exports.JPType.EXT16;
            valueWriter.ushort = length;
        }
        else if (length < 0x100000000) {
            valueWriter.ubyte = exports.JPType.EXT32;
            valueWriter.uint = length;
        }
        else {
            this.throwError(`Too large Symbol length: ${length} in file ` + this.fileName);
        }
        valueWriter.ubyte = exports.JPExtType.Symbol;
        valueWriter.overwrite(extBuffer.return(), valueWriter.offset, true);
        return length;
    }
    ;
    /**
     * Writes a `RegEx` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeRegEx(valueWriter, object) {
        const extBuffer = new BiWriter(Buffer.alloc(512), { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
        const src = object.source;
        const flags = object.flags;
        var length = 0;
        length += this.encodeString(extBuffer, src, false);
        length += this.encodeString(extBuffer, flags, false);
        extBuffer.trim();
        if (length < 0x100) {
            valueWriter.ubyte = exports.JPType.EXT8;
            valueWriter.ubyte = length;
        }
        else if (length < 0x10000) {
            valueWriter.ubyte = exports.JPType.EXT16;
            valueWriter.ushort = length;
        }
        else if (length < 0x100000000) {
            valueWriter.ubyte = exports.JPType.EXT32;
            valueWriter.uint = length;
        }
        else {
            this.throwError(`Too large RegEx length: ${length} in file ` + this.fileName);
        }
        valueWriter.ubyte = exports.JPExtType.RegEx;
        valueWriter.overwrite(extBuffer.return(), valueWriter.offset, true);
        return length;
    }
    ;
    /**
     * Writes a `TypedArray` or `Buffer` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeBinary(valueWriter, object) {
        var length = 1;
        const byteLength = object.byteLength;
        if (byteLength < 0x100) {
            valueWriter.ubyte = exports.JPType.EXT8;
            valueWriter.ubyte = byteLength;
            length++;
        }
        else if (byteLength < 0x10000) {
            valueWriter.ubyte = exports.JPType.EXT16;
            valueWriter.ushort = byteLength;
            length += 2;
        }
        else if (byteLength < 0x100000000) {
            valueWriter.ubyte = exports.JPType.EXT32;
            valueWriter.uint32 = byteLength;
            length += 4;
        }
        else {
            this.throwError(`Buffer ranged too large. ${byteLength} in file ` + this.fileName);
        }
        if (object instanceof Buffer) {
            valueWriter.ubyte = exports.JPExtType.Buffer;
            length++;
            valueWriter.overwrite(object, valueWriter.offset, true);
            length += object.length;
        }
        else {
            if (object instanceof Int8Array) {
                valueWriter.ubyte = exports.JPExtType.Int8Array;
            }
            else if (object instanceof Uint8Array) {
                valueWriter.ubyte = exports.JPExtType.Uint8Array;
            }
            else if (object instanceof Uint8ClampedArray) {
                valueWriter.ubyte = exports.JPExtType.Uint8ClampedArray;
            }
            else if (object instanceof Int16Array) {
                valueWriter.ubyte = exports.JPExtType.Int16Array;
            }
            else if (object instanceof Uint16Array) {
                valueWriter.ubyte = exports.JPExtType.Uint16Array;
            }
            else if (object instanceof Int32Array) {
                valueWriter.ubyte = exports.JPExtType.Int32Array;
            }
            else if (object instanceof Uint32Array) {
                valueWriter.ubyte = exports.JPExtType.Uint32Array;
            }
            else if (object instanceof Float32Array) {
                valueWriter.ubyte = exports.JPExtType.Float32Array;
            }
            else if (object instanceof Float64Array) {
                valueWriter.ubyte = exports.JPExtType.Float64Array;
            }
            else if (object instanceof BigInt64Array) {
                valueWriter.ubyte = exports.JPExtType.BigInt64Array;
            }
            else if (object instanceof BigUint64Array) {
                valueWriter.ubyte = exports.JPExtType.BigUint64Array;
                // @ts-ignore
            }
            else if (object instanceof Float16Array) {
                valueWriter.ubyte = exports.JPExtType.Float16Array;
            }
            else {
                this.throwError(' Unknown Buffer type in file ' + this.fileName);
            }
            length++;
            const uData = new Uint8Array(object.buffer);
            valueWriter.overwrite(uData, valueWriter.offset, true);
            length += uData.length;
        }
        return length;
    }
    ;
    /**
     * Writes a `Date` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    encodeDate(valueWriter, object) {
        const TIMESTAMP32_MAX_SEC = 0x100000000 - 1; // 32-bit unsigned int
        const TIMESTAMP64_MAX_SEC = 0x400000000 - 1; // 34-bit unsigned int
        const msec = object.getTime();
        const _sec = Math.floor(msec / 1e3);
        const _nsec = (msec - _sec * 1e3) * 1e6;
        // Normalizes { sec, nsec } to ensure nsec is unsigned.
        const nsecInSec = Math.floor(_nsec / 1e9);
        const sec = _sec + nsecInSec;
        const nsec = _nsec - nsecInSec * 1e9;
        valueWriter.ubyte = exports.JPType.EXT8;
        if (sec >= 0 && nsec >= 0 && sec <= TIMESTAMP64_MAX_SEC) {
            // Here sec >= 0 && nsec >= 0
            if (nsec === 0 && sec <= TIMESTAMP32_MAX_SEC) {
                // timestamp 32 = { sec32 (unsigned) }
                valueWriter.ubyte = 4;
                valueWriter.ubyte = exports.JPExtType.Date;
                valueWriter.uint32 = sec >>> 0;
                return 7;
            }
            else {
                valueWriter.ubyte = 8;
                valueWriter.ubyte = exports.JPExtType.Date;
                // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
                const secHigh = sec / 0x100000000;
                const secLow = sec & 0xffffffff;
                // nsec30 | secHigh2
                valueWriter.uint32 = ((nsec << 2) | (secHigh & 0x3)) >>> 0;
                // secLow32
                valueWriter.uint32 = secLow >>> 0;
                return 11;
            }
        }
        else {
            // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
            valueWriter.ubyte = 12;
            valueWriter.ubyte = exports.JPExtType.Date;
            valueWriter.uint32 = nsec >>> 0;
            valueWriter.int64 = sec;
            return 15;
        }
    }
    ;
    ////////////////////////
    // #region FINALIZE
    ////////////////////////
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
    buildHeader(endian) {
        if (endian) {
            this.endian = endian;
        }
        if (BigInt(this.HEADER_SIZE) + this.DATA_SIZE > BigInt(0x100000000)) {
            this.LargeFile = 1;
        }
        const bw = new BiWriter(Buffer.alloc(this.HEADER_SIZE), { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
        bw.endian = this.endian;
        bw.uint16 = this.MAGIC;
        bw.uint8 = this.VERSION_MAJOR;
        bw.uint8 = this.VERSION_MINOR;
        bw.uint8 = this.HEADER_SIZE;
        bw.bit1 = this.LargeFile;
        bw.bit1 = this.Compressed;
        bw.bit1 = this.Crc32;
        bw.bit1 = this.Encrypted;
        if (this.Encrypted == 0)
            this.EncryptionExcluded = 0;
        bw.bit1 = this.EncryptionExcluded;
        bw.bit1 = this.KeyStripped;
        bw.bit1 = 0; // FLAG6
        bw.bit1 = 0; // FLAG7
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
        this.headerBuffer = bw.get();
        return this.headerBuffer;
    }
    ;
    finalizeBuffers() {
        if (this.strWriter == null || this.valueWriter == null) {
            this.throwError(" Didn't create writers. " + this.fileName);
        }
        this.valueWriter.push(this.strWriter.data, true);
        this.valueWriter.trim();
        this.strWriter.deleteFile();
        this.compWriter = this.valueWriter;
        this.compWriter.trim();
        if (this.useFile) {
            this.compWriter.renameFile(this.fileName);
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
    }
    ;
    /**
     * Can stip or include the key value in file
     *
     * Can also set your own key.
     *
     * @param {boolean?} EncryptionExcluded - remove key from file
     * @param {number?} Encryptionkey - 32 bit number
     */
    encrypt(EncryptionExcluded, Encryptionkey) {
        this.Encrypted = 1;
        this.EncryptionExcluded = EncryptionExcluded ? 1 : 0;
        if (this.compWriter == null) {
            this.throwError("Writer not created for encryption. " + this.fileName);
        }
        const cypter = new Crypt(Encryptionkey);
        this.encryptionKey = cypter.key;
        const cryptBuffer = cypter.encrypt(this.compWriter.data);
        this.compWriter.gotoStart();
        this.compWriter.overwrite(cryptBuffer, 0, true);
        this.compWriter.trim();
        this.compWriter.commit();
        return this.compWriter.size;
    }
    ;
    /**
     * Compresses data
     */
    compress() {
        this.Compressed = 1;
        if (this.compWriter == null) {
            this.throwError(" Writer not created for compression. " + this.fileName);
        }
        this.compWriter.gotoStart();
        const compBuffer = deflateBuffer(this.compWriter);
        this.compWriter.gotoStart();
        this.compWriter.overwrite(compBuffer, 0, true);
        this.compWriter.trim();
        this.compWriter.commit();
        return this.compWriter.size;
    }
    ;
    /**
     * Creates CRC hash
     */
    CRC() {
        this.Crc32 = 1;
        if (this.compWriter == null) {
            this.throwError(" Writer not created for CRC. " + this.fileName);
        }
        if (!this.useFile) {
            const data = this.compWriter.data;
            this.CRC32 = CRC32(data, 0) >>> 0;
            return;
        }
        else {
            let crc = 0;
            const CHUNK_SIZE = 0x2000; // 8192 bytes
            for (let position = 0; position <= this.compWriter.size;) {
                this.compWriter.goto(position);
                const buffer = this.compWriter.extract(Math.min(CHUNK_SIZE, this.compWriter.size - position));
                if (buffer.length == 0)
                    break;
                crc = CRC32(buffer, crc);
                position += buffer.length;
            }
            this.CRC32 = crc >>> 0;
            this.CRC32Hash = this.CRC32;
        }
    }
    ;
}

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
function stringifyFix(_this, key) {
    if (key === undefined) {
        return "undefined";
    }
    else if (key instanceof RegExp) {
        const src = key.source;
        const flags = key.flags;
        return { regexSrc: src, regexFlags: flags };
    }
    else if (typeof key == "symbol") {
        const keyCheck = Symbol.keyFor(key);
        const global = !!keyCheck;
        var keyed = keyCheck ?? key.description;
        keyed = keyed ?? "";
        return { symbolGlobal: global, symbolKey: keyed };
    }
    else if (key instanceof Set) {
        const array = [];
        for (const item of key) {
            array.push(item);
        }
        return array;
    }
    else if (key instanceof Map) {
        return Array.from(key.entries());
    }
    else if (typeof key === "bigint") {
        const MIN_SAFE = BigInt(Number.MIN_SAFE_INTEGER);
        const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
        if (key >= MIN_SAFE && key <= MAX_SAFE) {
            return Number(key);
        }
        else {
            return key.toString();
        }
    }
    else {
        return key;
    }
}
const STATE_ARRAY = "array";
const STATE_SET = "set";
const STATE_MAP_KEY = "map_key";
const STATE_MAP_VALUE = "map_value";
const STATE_OBJECT_KEY = "object_key";
const STATE_OBJECT_VALUE = "object_value";
const mapKeyConverter = (key) => {
    if (typeof key === "string" || typeof key === "number" || typeof key == "symbol") {
        return key;
    }
    throw new Error("The type of key must be string or number but " + typeof key);
};
class StackPool {
    constructor() {
        this.stack = [];
        this.stackHeadPosition = -1;
    }
    get length() {
        return this.stackHeadPosition + 1;
    }
    ;
    top() {
        return this.stack[this.stackHeadPosition];
    }
    ;
    pushArrayState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_ARRAY;
        state.position = 0;
        state.size = size;
        state.array = new Array(size);
    }
    ;
    pushSetState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_SET;
        state.position = 0;
        state.size = size;
        state.set = new Set();
    }
    ;
    pushMapState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_MAP_KEY;
        state.readCount = 0;
        state.size = size;
        state.map = new Map();
    }
    ;
    pushObjectState(size) {
        const state = this.getUninitializedStateFromPool();
        state.type = STATE_OBJECT_KEY;
        state.readCount = 0;
        state.size = size;
        state.object = {};
    }
    ;
    getUninitializedStateFromPool() {
        this.stackHeadPosition++;
        if (this.stackHeadPosition === this.stack.length) {
            const partialState = {
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
            this.stack.push(partialState);
        }
        return this.stack[this.stackHeadPosition];
    }
    ;
    release(state) {
        const topStackState = this.stack[this.stackHeadPosition];
        if (topStackState !== state) {
            throw new Error("Invalid stack state. Released state is not on top of the stack.");
        }
        if (state.type === STATE_SET) {
            const partialState = state;
            partialState.size = 0;
            partialState.set = undefined;
            partialState.position = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_ARRAY) {
            const partialState = state;
            partialState.size = 0;
            partialState.array = undefined;
            partialState.position = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_MAP_KEY || state.type === STATE_MAP_VALUE) {
            const partialState = state;
            partialState.size = 0;
            partialState.map = undefined;
            partialState.readCount = 0;
            partialState.type = undefined;
        }
        if (state.type === STATE_OBJECT_KEY || state.type === STATE_OBJECT_VALUE) {
            const partialState = state;
            partialState.size = 0;
            partialState.object = undefined;
            partialState.readCount = 0;
            partialState.type = undefined;
        }
        this.stackHeadPosition--;
    }
    ;
    reset() {
        this.stack.length = 0;
        this.stackHeadPosition = -1;
    }
    ;
}
/**
 * Create with `DecoderOptions`
 */
class JPDecodeAsync extends JPBaseAsync {
    /**
     * Set up with basic options.
     *
     * @param {DecoderOptions?} options - options for decoding
     */
    constructor(options) {
        super();
        this.mapKeyConverter = mapKeyConverter;
        this.stack = new StackPool();
        this.stringsList = [];
        /**
         * Endianness. Defaults to `little`
         */
        this.endian = "little";
        /**
         * Converts return to valid JSON
         */
        this.makeJSON = false;
        /**
         * Ensures all 64 bit values return as `bigint`
         */
        this.enforceBigInt = false;
        /**
         * File Buffer
         */
        this.buffer = null;
        /**
         * Direct objects for any symbols that were encoded.
         */
        this.symbolList = [];
        /**
         * If a temp file was needed.
         */
        this.tempCreated = false;
        /**
         * If the file buffer has extensions types in use.
         */
        this.hasExtensions = false;
        /**
         * If the data is acceptable JSON data.
         */
        this.validJSON = true;
        /**
         * Computed CRC32 hash value.
         */
        this.CRC32Hash = 0;
        /**
         * CRC32 Hash on file.
         */
        this.CRC32OnFile = 0;
        this.extensionCodec = options?.extensionCodec ?? JPExtensionCodec.defaultCodec;
        this.context = options?.context; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined
        this.keysArray = options?.keysArray ? options.keysArray : [];
        this.encryptionKey = options?.encryptionKey ? options.encryptionKey : 0;
        this.enforceBigInt = options?.enforceBigInt ? options.enforceBigInt : false;
        this.makeJSON = options?.makeJSON ? options.makeJSON : false;
    }
    ;
    clone() {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // @ts-ignore
        const clone = new JPDecodeAsync({
            extensionCodec: this.extensionCodec,
            context: this.context,
            keysArray: this.keysArray,
            encryptionKey: this.encryptionKey,
            enforceBigInt: this.enforceBigInt,
            makeJSON: this.makeJSON,
        });
        clone.fileName = this.fileName;
        // TODO may need more
        return clone;
    }
    ;
    /**
     * Basic decoding, will run options that were set in constructor.
     *
     * If passed a `string`, will assume it is a file path to read the file from.
     *
     * This will trigger a stream like mode where the whole file isn't loaded all at once for larger files.
     *
     * @param bufferOrSourcePath - `Buffer` of the JamPack data or the file path to a JamPack file.
     */
    async decode(bufferOrSourcePath) {
        if (this.entered) {
            const instance = this.clone();
            return await instance.decode(bufferOrSourcePath);
        }
        if (typeof bufferOrSourcePath != "string") {
            await this.setBuffer(bufferOrSourcePath);
        }
        else {
            this.fileName = bufferOrSourcePath;
            await this.checkFilePath(this.fileName);
        }
        try {
            this.entered = true;
            await this.reinitializeState();
            if (this.valueReaderAsync == null) {
                this.throwError(" No value reader set. " + this.fileName);
            }
            this.stringsList = await this.createStringList();
            const object = await this.doDecode(this.valueReaderAsync);
            if (this.tempCreated) {
                await this.valueReaderAsync.deleteFile();
                await this.valueReaderAsync.close();
            }
            if (this.makeJSON && !this.validJSON) {
                return JSON.parse(JSON.stringify(object, stringifyFix));
            }
            return object;
        }
        catch (err) {
            console.error(err);
            return;
        }
        finally {
            this.entered = false;
        }
    }
    ;
    async checkFilePath(filePath) {
        if (fileExists(filePath)) {
            const bytes = peakBytesSync(filePath, 40);
            var biTest = new BiReaderAsync(bytes, { enforceBigInt: this.enforceBigInt });
            await this.testHeader(biTest);
            biTest.close();
            if (!this.LargeFile) {
                this.buffer = await fsp.readFile(filePath);
            }
        }
        else {
            this.throwError(`Couldn't find file. ` + filePath);
        }
        return;
    }
    ;
    async testHeader(br) {
        const MAGICS = await br.uint16();
        if (!(MAGICS == 0x504A || MAGICS == 0x4A50)) {
            this.throwError(`File magics incorrect. Expecting 0x504A or 0x4A50, but got 0x${MAGICS.toString(16).padStart(4, "0")} ` + this.fileName);
        }
        if (MAGICS == 0x4A50) {
            this.endian = "big";
        }
        const V_MAJOR = await br.uint8();
        const V_MINOR = await br.uint8();
        this.HEADER_SIZE = await br.uint8();
        this.LargeFile = await br.bit1();
        this.Compressed = await br.bit1();
        this.Crc32 = await br.bit1();
        this.Encrypted = await br.bit1();
        this.EncryptionExcluded = await br.bit1();
        this.KeyStripped = await br.bit1();
        await br.bit1(); // FLAG6
        await br.bit1(); // FLAG7
        await br.uint8(); // RESV_6 FLAG8-15
        await br.uint8(); // RESV_7 FLAG16-23
        this.VALUE_SIZE = await br.uint64();
        this.STR_SIZE = await br.uint64();
        this.DATA_SIZE = await br.uint64();
        const V_NUMBER = parseFloat(`${V_MAJOR}.${V_MINOR}`);
        if (V_NUMBER > VERSION_NUMBER) {
            this.addError(`File was encoded in a more advanced version of this package which may cause issues. Package: ${VERSION_NUMBER} - File: ${V_NUMBER} ` + this.fileName);
        }
        if (this.LargeFile && (br.size > MAX_BUFFER || (this.STR_SIZE + this.VALUE_SIZE) > MAX_BUFFER)) {
            this.useFile = true;
        }
        if (this.EncryptionExcluded && this.encryptionKey == 0) {
            this.throwError(' The encryption key is not included in the file and the key was not set in the decoder. Can not decode. ' + this.fileName);
        }
        if (this.KeyStripped && this.keysArray.length == 0) {
            this.throwError(' The keysArray was removed from the file and not set in the decoder. Can not decode. ' + this.fileName);
        }
        // extra headers
        if (this.Crc32) {
            this.CRC32 = await br.uint32();
            this.CRC32OnFile = this.CRC32;
        }
        if (this.Encrypted && !this.EncryptionExcluded) {
            this.encryptionKey = await br.uint32();
        }
    }
    ;
    /**
     * Sets up valueReader & strReader. Will decomp and decrypt as well.
     *
     * If a temp file is made, will have to delete after.
     */
    async reinitializeState() {
        if (this.useFile) {
            if (this.fileReaderAsync != null) {
                await this.fileReaderAsync.close();
                this.fileReaderAsync = null;
            }
            const windowSize = this.LargeFile ? this.growthIncrement : 0;
            this.compReaderAsync = new BiReaderAsync(this.fileName, { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
            this.compReaderAsync.endian = this.endian;
            await this.compReaderAsync.open();
            await this.compReaderAsync.goto(this.HEADER_SIZE);
            this.tempCreated = false;
            if (this.Encrypted) {
                // make comp file without header
                const compWriter = new BiWriterAsync(this.fileName + ".comp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                compWriter.unrestrict();
                compWriter.endian = this.endian;
                await compWriter.open();
                await compWriter.overwrite(await this.compReaderAsync.subarray(this.HEADER_SIZE, this.compReaderAsync.size - this.HEADER_SIZE), compWriter.offset, true);
                await compWriter.trim();
                this.tempCreated = true;
                var finalSize = 0;
                if (this.Compressed) {
                    finalSize = Number(this.DATA_SIZE);
                }
                else {
                    finalSize = Number(this.VALUE_SIZE + this.STR_SIZE);
                }
                await this.decrypt(compWriter, null, finalSize);
                await compWriter.close();
                this.compReaderAsync = new BiReaderAsync(this.fileName + ".comp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                this.compReaderAsync.endian = this.endian;
                this.compReaderAsync.unrestrict();
                this.compReaderAsync.open();
            }
            if (this.Compressed) {
                // check if comp file was made
                if (this.tempCreated) {
                    // compReader should be just the data
                    const tempcompWriter = new BiWriterAsync(this.fileName + ".comp.tmp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                    tempcompWriter.endian = this.endian;
                    await tempcompWriter.open();
                    await inflateFileAsync(this.compReaderAsync, tempcompWriter);
                    await this.compReaderAsync.writeMode(true);
                    this.compReaderAsync.gotoStart();
                    await this.compReaderAsync.overwrite(await tempcompWriter.subarray(0, tempcompWriter.offset), this.compReaderAsync.offset, true);
                    await this.compReaderAsync.trim();
                    await this.compReaderAsync.writeMode(false);
                    await tempcompWriter.deleteFile();
                }
                else {
                    // split off header
                    const compWriter = new BiWriterAsync(this.fileName + ".comp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                    compWriter.endian = this.endian;
                    await compWriter.open();
                    await compWriter.overwrite(await this.compReaderAsync.subarray(this.HEADER_SIZE, this.compReaderAsync.size - this.HEADER_SIZE), compWriter.offset, true);
                    await compWriter.trim();
                    await compWriter.close();
                    const compReader = new BiReaderAsync(this.fileName + ".comp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                    compReader.endian = this.endian;
                    compReader.unrestrict();
                    const tempcompWriter = new BiWriterAsync(this.fileName + ".comp.tmp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                    tempcompWriter.endian = this.endian;
                    await tempcompWriter.open();
                    this.tempCreated = true;
                    await inflateFileAsync(compReader, tempcompWriter);
                    await compReader.writeMode(true);
                    compReader.gotoStart();
                    await compReader.overwrite(await tempcompWriter.subarray(0, tempcompWriter.offset), compReader.offset, true);
                    await compReader.trim();
                    await compReader.writeMode(false);
                    await tempcompWriter.deleteFile();
                    this.compReaderAsync = compReader;
                }
            }
            if (this.Crc32) {
                const CHUNK_SIZE = 0x2000; // 8192 bytes
                var crc = 0;
                var start = this.HEADER_SIZE;
                if (this.tempCreated) {
                    start = 0;
                }
                await this.compReaderAsync.goto(start);
                for (let position = start; position <= this.compReaderAsync.size;) {
                    const buffer = await this.compReaderAsync.subarray(position, Math.min(CHUNK_SIZE, this.compReaderAsync.size - position));
                    if (buffer.length == 0)
                        break;
                    crc = CRC32(buffer, crc);
                    position += buffer.length;
                }
                this.CRC32Hash = crc >>> 0;
                if (this.CRC32Hash != this.CRC32OnFile) {
                    this.addError(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32OnFile} but got ${this.CRC32Hash}. ` + this.fileName);
                }
            }
            var totalSize = 0n;
            if (this.tempCreated) {
                totalSize = BigInt(this.compReaderAsync.size);
                await this.compReaderAsync.open();
                this.valueReaderAsync = new BiReaderAsync(this.fileName + ".comp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                this.strReaderAsync = new BiReaderAsync(this.fileName + ".comp", { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                this.valueReaderAsync.fd = this.compReaderAsync.fd;
                this.valueReaderAsync.endian = this.compReaderAsync.endian;
                this.valueReaderAsync.size = this.compReaderAsync.size;
                this.valueReaderAsync.bitSize = this.compReaderAsync.bitSize;
                this.valueReaderAsync.growthIncrement = this.compReaderAsync.growthIncrement;
                this.strReaderAsync.fd = this.compReaderAsync.fd;
                this.strReaderAsync.endian = this.compReaderAsync.endian;
                this.strReaderAsync.size = this.compReaderAsync.size;
                this.strReaderAsync.bitSize = this.compReaderAsync.bitSize;
                this.strReaderAsync.growthIncrement = this.compReaderAsync.growthIncrement;
                await this.strReaderAsync.goto(Number(this.VALUE_SIZE));
            }
            else {
                totalSize = BigInt(this.compReaderAsync.size - this.HEADER_SIZE);
                await this.compReaderAsync.open();
                this.valueReaderAsync = new BiReaderAsync(this.fileName, { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                this.strReaderAsync = new BiReaderAsync(this.fileName, { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
                this.valueReaderAsync.fd = this.compReaderAsync.fd;
                this.valueReaderAsync.endian = this.compReaderAsync.endian;
                this.valueReaderAsync.size = this.compReaderAsync.size;
                this.valueReaderAsync.bitSize = this.compReaderAsync.bitSize;
                this.valueReaderAsync.growthIncrement = this.compReaderAsync.growthIncrement;
                await this.valueReaderAsync.goto(this.HEADER_SIZE);
                this.strReaderAsync.fd = this.compReaderAsync.fd;
                this.strReaderAsync.endian = this.compReaderAsync.endian;
                this.strReaderAsync.size = this.compReaderAsync.size;
                this.strReaderAsync.bitSize = this.compReaderAsync.bitSize;
                this.strReaderAsync.growthIncrement = this.compReaderAsync.growthIncrement;
                await this.strReaderAsync.goto(this.HEADER_SIZE + Number(this.VALUE_SIZE));
            }
            if (this.VALUE_SIZE + this.STR_SIZE != totalSize) {
                this.addError(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${totalSize}. ` + this.fileName);
            }
        }
        else {
            if (this.buffer == null) {
                this.throwError(" Buffer not set. " + this.fileName);
            }
            this.fileReaderAsync = new BiReaderAsync(this.buffer, { enforceBigInt: this.enforceBigInt });
            this.fileReaderAsync.endian = this.endian;
            await this.fileReaderAsync.goto(this.HEADER_SIZE);
            var decomBuffer = this.buffer.subarray(this.HEADER_SIZE, this.buffer.length);
            this.compReaderAsync = new BiReaderAsync(decomBuffer, { enforceBigInt: this.enforceBigInt });
            this.compReaderAsync.endian = this.endian;
            if (this.Encrypted) {
                var finalSize = Number(this.VALUE_SIZE + this.STR_SIZE);
                if (this.Compressed) {
                    finalSize = Number(this.DATA_SIZE);
                }
                decomBuffer = await this.decrypt(null, decomBuffer, finalSize);
                this.compReaderAsync = new BiReaderAsync(decomBuffer, { enforceBigInt: this.enforceBigInt });
                this.compReaderAsync.endian = this.endian;
            }
            if (this.Compressed) {
                decomBuffer = await inflateBufferAsync(this.compReaderAsync);
                this.compReaderAsync = new BiReaderAsync(decomBuffer, { enforceBigInt: this.enforceBigInt });
                this.compReaderAsync.endian = this.endian;
            }
            if (this.Crc32) {
                const data = this.compReaderAsync.data;
                this.CRC32Hash = CRC32(data, 0) >>> 0;
                if (this.CRC32Hash != this.CRC32OnFile) {
                    this.addError(`File DID NOT pass CRC32 check, may be corrupt. Expecting ${this.CRC32OnFile} but got ${this.CRC32Hash}. ` + this.fileName);
                }
            }
            if (this.VALUE_SIZE + this.STR_SIZE != BigInt(this.compReaderAsync.size)) {
                this.addError(`File size DID NOT match headers, may be corrupt. Expecting ${this.VALUE_SIZE + this.STR_SIZE} but got ${this.compReaderAsync.size}. ` + this.fileName);
            }
            this.valueReaderAsync = new BiReaderAsync(await this.compReaderAsync.extract(Number(this.VALUE_SIZE), true));
            console.log("valueReaderAsync", this.compReaderAsync.offset, await this.valueReaderAsync.get());
            this.valueReaderAsync.endian = this.endian;
            this.strReaderAsync = new BiReaderAsync(await this.compReaderAsync.extract(Number(this.STR_SIZE), true));
            console.log("strReaderAsync", this.compReaderAsync.offset, await this.strReaderAsync.get());
            this.strReaderAsync.endian = this.endian;
        }
    }
    ;
    async setBuffer(buffer) {
        this.buffer = ensureBuffer(buffer);
        this.fileReaderAsync = new BiReaderAsync(this.buffer, { enforceBigInt: this.enforceBigInt });
        await this.testHeader(this.fileReaderAsync);
        await this.fileReaderAsync.close();
        this.fileReaderAsync = null;
    }
    ;
    async createStringList() {
        if (this.strReaderAsync == null) {
            this.throwError(" string reader not set. " + this.fileName);
        }
        DECODE: while (true) {
            const headByte = await this.strReaderAsync.ubyte();
            let object;
            if ((headByte >= exports.JPType.ARRAY_0 && headByte <= exports.JPType.ARRAY_15) || // arrays
                (headByte >= exports.JPType.ARRAY8 && headByte <= exports.JPType.ARRAY32)) {
                var size = 0;
                if (headByte <= exports.JPType.ARRAY_15) {
                    size = headByte - exports.JPType.ARRAY_0;
                }
                else if (headByte === exports.JPType.ARRAY8) {
                    size = await this.strReaderAsync.ubyte();
                }
                else if (headByte === exports.JPType.ARRAY16) {
                    size = await this.strReaderAsync.uint16();
                }
                else if (headByte === exports.JPType.ARRAY32) {
                    size = await this.strReaderAsync.uint32();
                }
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if ((headByte >= exports.JPType.STR_0 && headByte <= exports.JPType.STR_15) || // strings
                (headByte >= exports.JPType.STR8 && headByte <= exports.JPType.STR32)) {
                var size = 0;
                if (headByte <= exports.JPType.STR_15) {
                    size = headByte - exports.JPType.STR_0;
                }
                else if (headByte === exports.JPType.STR8) {
                    size = await this.strReaderAsync.ubyte();
                }
                else if (headByte === exports.JPType.STR16) {
                    size = await this.strReaderAsync.uint16();
                }
                else if (headByte === exports.JPType.STR32) {
                    size = await this.strReaderAsync.uint32();
                }
                object = await this.strReaderAsync.string({ length: size });
            }
            else {
                this.throwError(`Invalid data in string area. 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }
            const stack = this.stack;
            while (stack.length > 0) {
                // arrays
                const state = stack.top();
                if (state.type === STATE_ARRAY) {
                    state.array[state.position] = object;
                    state.position++;
                    if (state.position === state.size) {
                        object = state.array;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else {
                    this.throwError(' Should only have an array in the string data, found type ' + state.type + " in file " + this.fileName);
                }
            }
            return object;
        }
    }
    ;
    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     *
     * NOTE: This function is for extention use, not direct use. Use `decodeAsync` instead.
     *
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    async doDecodeAsync(bufferOrReader) {
        var reader = bufferOrReader;
        if (reader instanceof Buffer) {
            const windowSize = this.LargeFile ? this.growthIncrement : 0;
            reader = new BiReaderAsync(reader, { windowSize: windowSize, enforceBigInt: this.enforceBigInt });
            reader.endian = this.endian;
        }
        if (!(reader instanceof BiReaderAsync) || reader == null) {
            this.throwError(" Value reader not set. " + this.fileName);
        }
        if (this.strReaderAsync == null) {
            this.throwError(" String reader not set. " + this.fileName);
        }
        try {
            return await this.doDecode(reader);
        }
        catch (err) {
            // @ts-ignore
            throw new Error(err);
        }
    }
    ;
    /**
     * Runs a raw decode on the passed value buffer as `Buffer` or `BiReader`. Return data wherever it ends based on the start value.
     *
     * NOTE: This function is for extention use, not direct use. Use `decode` instead.
     *
     * @param bufferOrReader - `Buffer` or `BiReader`
     * @returns Decoded data
     */
    async doDecode(bufferOrReader) {
        var reader = bufferOrReader;
        if (reader instanceof Buffer) {
            reader = new BiReaderAsync(reader, { enforceBigInt: this.enforceBigInt });
            reader.endian = this.endian;
        }
        if (!(reader instanceof BiReaderAsync) || reader == null) {
            this.throwError(" Value reader not set. " + this.fileName);
        }
        if (this.strReaderAsync == null) {
            this.throwError(" String reader not set. " + this.fileName);
        }
        reader = reader;
        let object;
        DECODE: while (true) {
            const headByte = await reader.ubyte();
            if (headByte < exports.JPType.OBJECT_0) {
                // positive fixint 0x00 - 0x7f
                object = headByte;
            }
            else if (headByte < exports.JPType.ARRAY_0) {
                // fix object 0x80 - 0x8f
                const size = headByte - 0x80;
                if (size !== 0) {
                    this.pushObjectState(size);
                    continue DECODE;
                }
                else {
                    object = {};
                }
            }
            else if (headByte < exports.JPType.KEY_0) {
                //fixarray
                const size = headByte - 0x90;
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if (headByte < exports.JPType.STR_0) {
                //fixkey (only used in stripping)
                const index = headByte - 0xA0;
                if (!this.keysArray[index]) {
                    this.addError(`Did not find key value for index ` + index + " in file " + this.fileName);
                }
                object = this.keysArray[index];
            }
            else if (headByte < exports.JPType.NULL) {
                //fixstr
                const index = headByte - 0xB0;
                if (this.stringsList[index] === undefined) {
                    this.addError(`Did not find string value for index ` + index + " in file " + this.fileName);
                }
                object = this.stringsList[index];
            }
            else if (headByte == exports.JPType.NULL) {
                object = null;
            }
            else if (headByte == exports.JPType.UNDEFINED) {
                object = undefined;
                this.validJSON = false;
            }
            else if (headByte == exports.JPType.BOOL_FALSE) {
                object = false;
            }
            else if (headByte == exports.JPType.BOOL_TRUE) {
                object = true;
            }
            else if (headByte == exports.JPType.FINISHED ||
                headByte == exports.JPType.UNUSED_C6) {
                return object;
            }
            else if (headByte == exports.JPType.LIST_END) {
                const state = this.stack.top();
                if (state.type != undefined) {
                    if (state.type == STATE_ARRAY) {
                        object = state.array;
                    }
                    else if (state.type == STATE_OBJECT_KEY || state.type == STATE_OBJECT_VALUE) {
                        object = state.object;
                    }
                    else if (state.type == STATE_MAP_KEY || state.type == STATE_MAP_VALUE) {
                        object = state.map;
                    }
                    this.stack.release(state);
                }
                return object;
            }
            else if (headByte <= exports.JPType.OBJECT32) {
                // non-fix object
                var size = 0;
                if (headByte === exports.JPType.OBJECT8) {
                    size = await reader.ubyte();
                }
                else if (headByte === exports.JPType.OBJECT16) {
                    size = await reader.uint16();
                }
                else if (headByte === exports.JPType.OBJECT32) {
                    size = await reader.uint32();
                }
                if (size !== 0) {
                    this.pushObjectState(size);
                    continue DECODE;
                }
                else {
                    object = {};
                }
            }
            else if (headByte === exports.JPType.FLOAT32) {
                object = await reader.float();
            }
            else if (headByte === exports.JPType.FLOAT64) {
                object = await reader.doublefloat();
            }
            else if (headByte === exports.JPType.UINT_8) {
                object = await reader.uint8();
            }
            else if (headByte === exports.JPType.UINT_16) {
                object = await reader.uint16();
            }
            else if (headByte === exports.JPType.UINT_32) {
                object = await reader.uint32();
            }
            else if (headByte === exports.JPType.UINT_64) {
                object = await reader.uint64();
                if (this.enforceBigInt) {
                    object = BigInt(object);
                }
                if (typeof object === "bigint") {
                    this.validJSON = false;
                }
            }
            else if (headByte === exports.JPType.INT_8) {
                object = await reader.int8();
            }
            else if (headByte === exports.JPType.INT_16) {
                object = await reader.int16();
            }
            else if (headByte === exports.JPType.INT_32) {
                object = await reader.int32();
            }
            else if (headByte === exports.JPType.INT_64) {
                object = await reader.int64();
                if (this.enforceBigInt) {
                    object = BigInt(object);
                }
                if (typeof object === "bigint") {
                    this.validJSON = false;
                }
            }
            else if (headByte <= exports.JPType.KEY32) {
                // nonfix key
                var index = 0;
                if (headByte === exports.JPType.KEY8) {
                    index = await reader.ubyte();
                }
                else if (headByte === exports.JPType.KEY16) {
                    index = await reader.uint16();
                }
                else if (headByte === exports.JPType.KEY32) {
                    index = await reader.uint32();
                }
                if (!this.keysArray[index]) {
                    this.addError(`Did not find key value for index ` + index + " in file " + this.fileName);
                }
                object = this.keysArray[index];
            }
            else if (headByte <= exports.JPType.STR32) {
                // non-fix string
                var index = 0;
                if (headByte === exports.JPType.STR8) {
                    index = await reader.ubyte();
                }
                else if (headByte === exports.JPType.STR16) {
                    index = await reader.uint16();
                }
                else if (headByte === exports.JPType.STR32) {
                    index = await reader.uint32();
                }
                if (this.stringsList[index] === undefined) {
                    this.addError(`Did not find string value for index ` + index + " in file " + this.fileName);
                }
                object = this.stringsList[index];
            }
            else if (headByte <= exports.JPType.ARRAY32) {
                // non-fix array
                var size = 0;
                if (headByte === exports.JPType.ARRAY8) {
                    size = await reader.ubyte();
                }
                else if (headByte === exports.JPType.ARRAY16) {
                    size = await reader.uint16();
                }
                else if (headByte === exports.JPType.ARRAY32) {
                    size = await reader.uint32();
                }
                if (size !== 0) {
                    this.pushArrayState(size);
                    continue DECODE;
                }
                else {
                    object = [];
                }
            }
            else if (headByte <= exports.JPType.EXT32) {
                this.hasExtensions = true;
                var size = 0;
                if (headByte === exports.JPType.EXT8) {
                    size = await reader.ubyte();
                }
                else if (headByte === exports.JPType.EXT16) {
                    size = await reader.uint16();
                }
                else if (headByte === exports.JPType.EXT32) {
                    size = await reader.uint32();
                }
                const type = await reader.ubyte();
                if (type == exports.JPExtType.Maps) {
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushMapState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Map();
                    }
                }
                else if (type == exports.JPExtType.Sets) {
                    this.validJSON = false;
                    if (size !== 0) {
                        this.pushSetState(size);
                        continue DECODE;
                    }
                    else {
                        object = new Set();
                    }
                }
                else {
                    object = await this.decodeExtension(reader, size, type);
                }
            }
            else if (headByte > exports.JPType.EXT32) {
                // negative fixint
                object = headByte - 0x100;
            }
            else {
                this.throwError(`Outside of index error 0x${headByte.toString(16).padStart(2, "0")} ` + this.fileName);
            }
            const stack = this.stack;
            while (stack.length > 0) {
                // arrays and maps
                const state = stack.top();
                if (state.type === STATE_ARRAY) {
                    state.array[state.position] = object;
                    state.position++;
                    if (state.position === state.size) {
                        object = state.array;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_SET) {
                    state.set.add(object);
                    state.position++;
                    if (state.position === state.size) {
                        object = state.set;
                        stack.release(state);
                    }
                    else {
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_OBJECT_KEY) {
                    if (object === "__proto__") {
                        this.throwError(" The key __proto__ is not allowed " + this.fileName);
                    }
                    state.key = this.mapKeyConverter(object);
                    state.type = STATE_OBJECT_VALUE;
                    continue DECODE;
                }
                else if (state.type === STATE_OBJECT_VALUE) {
                    state.object[state.key] = object;
                    state.readCount++;
                    if (state.readCount === state.size) {
                        object = state.object;
                        stack.release(state);
                    }
                    else {
                        state.key = null;
                        state.type = STATE_OBJECT_KEY;
                        continue DECODE;
                    }
                }
                else if (state.type === STATE_MAP_KEY) {
                    if (object === "__proto__") {
                        this.throwError(" The key __proto__ is not allowed " + this.fileName);
                    }
                    state.key = this.mapKeyConverter(object);
                    state.type = STATE_MAP_VALUE;
                    continue DECODE;
                }
                else if (state.type === STATE_MAP_VALUE) {
                    // it must be `state.type === State.MAP_VALUE` here
                    state.map.set(state.key, object);
                    state.readCount++;
                    if (state.readCount === state.size) {
                        object = state.map;
                        stack.release(state);
                    }
                    else {
                        state.key = null;
                        state.type = STATE_MAP_KEY;
                        continue DECODE;
                    }
                }
            }
            return object;
        }
    }
    ;
    pushMapState(size) {
        this.stack.pushMapState(size);
    }
    ;
    pushObjectState(size) {
        this.stack.pushObjectState(size);
    }
    ;
    pushArrayState(size) {
        this.stack.pushArrayState(size);
    }
    ;
    pushSetState(size) {
        this.stack.pushSetState(size);
    }
    ;
    async readString(headByte) {
        if (this.valueReaderAsync == null) {
            this.throwError(" Value reader not set. " + this.fileName);
        }
        var value = "";
        if ((headByte >= exports.JPType.STR_0 && headByte <= exports.JPType.STR_15) || // strings
            (headByte >= exports.JPType.STR8 && headByte <= exports.JPType.STR32)) {
            var index = 0;
            if (headByte <= exports.JPType.STR_15) {
                index = headByte - exports.JPType.STR_0;
            }
            else if (headByte === exports.JPType.STR8) {
                index = await this.valueReaderAsync.ubyte();
            }
            else if (headByte === exports.JPType.STR16) {
                index = await this.valueReaderAsync.uint16();
            }
            else if (headByte === exports.JPType.STR32) {
                index = await this.valueReaderAsync.uint32();
            }
            if (this.stringsList[index] === undefined) {
                this.addError(`Did not find string value for index ` + index + " in file " + this.fileName);
            }
            else {
                value = this.stringsList[index];
            }
        }
        return value;
    }
    ;
    async decodeExtension(valueReader, size, extType) {
        let retValue, data, holder;
        switch (extType) {
            case exports.JPExtType.Symbol:
                this.validJSON = false;
                // bool and string
                const global = await valueReader.ubyte() == exports.JPType.BOOL_TRUE ? true : false;
                var headByte = await valueReader.ubyte();
                const key = await this.readString(headByte);
                retValue = global ? Symbol.for(key) : Symbol(key);
                this.symbolList.push(retValue);
                break;
            case exports.JPExtType.RegEx:
                this.validJSON = false;
                // two strings
                const source = await this.readString(await valueReader.ubyte());
                const flags = await this.readString(await valueReader.ubyte());
                retValue = new RegExp(source, flags);
                break;
            case exports.JPExtType.Maps:
                this.validJSON = false;
                // handled before
                break;
            case exports.JPExtType.Sets:
                this.validJSON = false;
                // handled before
                break;
            case exports.JPExtType.BigUint64Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new BigUint64Array(holder.buffer);
                break;
            case exports.JPExtType.BigInt64Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new BigInt64Array(holder.buffer);
                break;
            case exports.JPExtType.Float64Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Float64Array(holder.buffer);
                break;
            case exports.JPExtType.Float32Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Float32Array(holder.buffer);
                break;
            case exports.JPExtType.Float16Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                // @ts-ignore
                if (typeof Float16Array !== 'undefined') {
                    // @ts-ignore
                    retValue = new Float16Array(holder.buffer);
                }
                break;
            case exports.JPExtType.Int32Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int32Array(holder.buffer);
                break;
            case exports.JPExtType.Uint32Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint32Array(holder.buffer);
                break;
            case exports.JPExtType.Uint16Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint16Array(holder.buffer);
                break;
            case exports.JPExtType.Int16Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int16Array(holder.buffer);
                break;
            case exports.JPExtType.Int8Array:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Int8Array(holder.buffer);
                break;
            case exports.JPExtType.Uint8Array:
                data = await valueReader.extract(size, true);
                retValue = new Uint8Array(data);
                break;
            case exports.JPExtType.Uint8ClampedArray:
                data = await valueReader.extract(size, true);
                holder = new Uint8Array(data);
                retValue = new Uint8ClampedArray(holder.buffer);
                break;
            case exports.JPExtType.Buffer:
                retValue = await valueReader.extract(size, true);
                retValue = Buffer.from(retValue);
                break;
            case exports.JPExtType.Date:
                data = await valueReader.extract(size, true);
                const br = new BiReaderAsync(data, { enforceBigInt: this.enforceBigInt });
                br.endian = this.endian;
                switch (br.size) {
                    case 4: {
                        // timestamp 32 = { sec32 }
                        const sec = await br.uint32();
                        const nsec = 0;
                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                        break;
                    }
                    case 8: {
                        // timestamp 64 = { nsec30, sec34 }
                        const nsec30AndSecHigh2 = await br.uint32();
                        const secLow32 = await br.uint32();
                        const sec = (nsec30AndSecHigh2 & 0x3) * 0x100000000 + secLow32;
                        const nsec = nsec30AndSecHigh2 >>> 2;
                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                        break;
                    }
                    case 12: {
                        // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
                        const nsec = await br.uint32();
                        const sec = Number(await br.int64());
                        retValue = new Date(sec * 1e3 + nsec / 1e6);
                    }
                    default:
                        this.throwError(`Unrecognized data size for timestamp (expected 4, 8, or 12): ${br.size} in file ` + this.fileName);
                }
                break;
        }
        if (retValue == undefined) {
            const data = await valueReader.extract(size, true);
            const br = new BiReaderAsync(data, { enforceBigInt: this.enforceBigInt });
            br.endian = this.endian;
            retValue = await this.extensionCodec.decodeAsync(br, this, extType, this.context);
        }
        return retValue;
    }
    ;
    //////////////
    // FINALIZE //
    //////////////
    async decrypt(br, buffer, finalSize) {
        const cypter = new Crypt(this.encryptionKey);
        if (!this.useFile) {
            if (buffer == null) {
                this.throwError(" Buffer to decrypt not set. " + this.fileName);
            }
            const decrypted = cypter.decrypt(buffer);
            if (decrypted.length != finalSize) {
                this.addError(`Decrypted buffer size of ${decrypted.length} wasn expected size of ${finalSize} in file ` + this.fileName);
            }
            return decrypted;
        }
        else {
            const CHUNK_SIZE = 16;
            await br.open();
            br.gotoStart();
            var buff = Buffer.alloc(0);
            var data;
            let bytesToProcess = br.size;
            let bytesStart = 0;
            let bytesRead = 0;
            let amount = Math.ceil(br.size / CHUNK_SIZE);
            for (let index = 0; index < amount; index++) {
                bytesRead = Math.min(CHUNK_SIZE, bytesToProcess);
                buff = await br.subarray(bytesStart, bytesRead);
                if (index == (amount - 1)) {
                    data = cypter.decrypt_block(buff, true);
                }
                else {
                    data = cypter.decrypt_block(buff);
                }
                if (data.length != 0) {
                    await br.overwrite(data, br.offset, true);
                }
                bytesStart += buff.length;
                bytesToProcess -= buff.length;
            }
            data = cypter.decrypt_final();
            if (data.length != 0) {
                await br.overwrite(data, br.offset, true);
            }
            await br.trim();
            if (br.size != finalSize) {
                this.addError(`Decrypted buffer size of ${br.size} was expected size of ${finalSize} in file ` + this.fileName);
            }
            return Buffer.alloc(0);
        }
    }
    ;
}

/**
 * Create with `EncoderOptions`
 */
class JPEncodeAsync extends JPBaseAsync {
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MAJOR() {
        return VERSION_MAJOR;
    }
    ;
    /**
     * Build verion number to check the file creation params
     */
    get VERSION_MINOR() {
        return VERSION_MINOR;
    }
    ;
    /**
     * Set up with basic options
     *
     * @param {EncoderOptions?} encodeOptions - options for encoding
     */
    constructor(encodeOptions) {
        super();
        this.stringList = new stringList();
        this.keyList = new stringList();
        this.depth = 0;
        ////////////////
        // CONSTANTS  //
        ////////////////
        /**
         * JP or PJ
         */
        this.MAGIC = 0x504A;
        /**
         * Endianness. Defaults to ``little``
         */
        this.endian = "little";
        this.CRC32Hash = 0;
        this.extensionCodec = encodeOptions?.extensionCodec ?? JPExtensionCodec.defaultCodec;
        this.context = encodeOptions?.context; // needs a type assertion because EncoderOptions has no context property when ContextType is undefined
        this.endian = encodeOptions?.endian ? encodeOptions.endian : "little";
        this.Encrypted = encodeOptions?.encrypt ? 1 : 0;
        this.EncryptionExcluded = encodeOptions?.stripEncryptKey ? 1 : 0;
        this.encryptionKey = encodeOptions?.encryptionKey ? encodeOptions.encryptionKey : 0;
        this.Compressed = encodeOptions?.compress ? 1 : 0;
        this.KeyStripped = encodeOptions?.stripKeys ? 1 : 0;
        this.Crc32 = encodeOptions?.CRC32 ? 1 : 0;
        this.growthIncrement = encodeOptions?.growthIncrement ? encodeOptions.growthIncrement : GROWTHINCREMENT_DEFAULT;
    }
    ;
    clone() {
        // Because of slightly special argument `context`,
        // type assertion is needed.
        // @ts-ignore
        const clone = new JPEncodeAsync({
            extensionCodec: this.extensionCodec,
            context: this.context,
            endian: this.endian,
            encrypt: this.Encrypted,
            stripEncryptKey: this.EncryptionExcluded,
            encryptionKey: this.encryptionKey,
            compress: this.Compressed,
            stripKeys: this.KeyStripped,
            CRC32: this.Crc32,
            growthIncrement: this.growthIncrement,
        });
        clone.fileName = this.fileName;
        clone.useFile = this.useFile;
        clone.valueWriterAsync = this.valueWriterAsync;
        clone.strWriterAsync = this.strWriterAsync;
        clone.keysArray = this.keysArray;
        clone.compWriterAsync = this.compWriterAsync;
        //TODO may need more here
        return clone;
    }
    ;
    /**
     * Basic encode, will run options that were set in constructor.
     *
     * @param {any} object - Data to encode
     * @param {string} filePath - Optional file path to write the file to directly
     * @returns {Buffer}
     */
    async encode(object, filePath) {
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
            await this.reinitializeState();
            if (this.valueWriterAsync == null || this.strWriterAsync == null) {
                this.throwError(" Didn't create writers. " + this.fileName);
            }
            await this.doEncode(this.valueWriterAsync, object, 1);
            await this.valueWriterAsync.ubyte(exports.JPType.FINISHED);
            await this.valueWriterAsync.trim();
            this.VALUE_SIZE = this.valueWriterAsync.size;
            await this.writeStringsData();
            await this.strWriterAsync.ubyte(exports.JPType.FINISHED);
            await this.strWriterAsync.trim();
            this.STR_SIZE = this.strWriterAsync.size;
            if (this.KeyStripped) {
                this.keysArray = this.keyList.getValues();
            }
            await this.finalizeBuffers();
            this.headerBuffer = await this.buildHeader();
            if (this.compWriterAsync == null) {
                this.throwError(" Didn't create writer. " + this.fileName);
            }
            const newOff = BigInt(this.compWriterAsync.size + this.headerBuffer.length);
            await this.compWriterAsync.unshift(this.headerBuffer, false);
            await this.compWriterAsync.goto(Number(newOff));
            await this.compWriterAsync.trim();
            await this.compWriterAsync.commit();
            if (this.useFile) {
                await this.compWriterAsync.renameFile(this.fileName);
                await this.compWriterAsync.close();
                return Buffer.alloc(0);
            }
            else {
                return await this.compWriterAsync.getData();
            }
        }
        catch (err) {
            console.error(err);
            return Buffer.alloc(0);
        }
        finally {
            this.entered = false;
        }
    }
    ;
    async reinitializeState() {
        if (this.useFile) {
            if (fileExists(this.fileName + ".values")) {
                await fsp.unlink(this.fileName + ".values");
            }
            this.valueWriterAsync = new BiWriterAsync(this.fileName + ".values", { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
            await this.valueWriterAsync.open();
            this.valueWriterAsync.endian = this.endian;
            if (fileExists(this.fileName + ".strings")) {
                await fsp.unlink(this.fileName + ".strings");
            }
            this.strWriterAsync = new BiWriterAsync(this.fileName + ".strings", { windowSize: this.growthIncrement, growthIncrement: this.growthIncrement });
            await this.strWriterAsync.open();
            this.strWriterAsync.endian = this.endian;
        }
        else {
            this.valueWriterAsync = new BiWriterAsync(Buffer.alloc(this.growthIncrement), { growthIncrement: this.growthIncrement });
            this.valueWriterAsync.endian = this.endian;
            this.strWriterAsync = new BiWriterAsync(Buffer.alloc(this.growthIncrement), { growthIncrement: this.growthIncrement });
            this.strWriterAsync.endian = this.endian;
        }
    }
    ;
    async doEncode(valueWriter, object, depth) {
        this.depth = depth;
        if (object === null) {
            return await this.encodeNull(valueWriter);
        }
        else if (object === undefined) {
            return await this.encodeUndefined(valueWriter);
        }
        else if (typeof object === "boolean") {
            return await this.encodeBoolean(valueWriter, object);
        }
        else if (typeof object === "number") {
            return await this.encodeNumber(valueWriter, object);
        }
        else if (typeof object === "string") {
            return await this.encodeString(valueWriter, object, false);
        }
        else if (typeof object === "bigint") {
            return await this.encodeBigInt64(valueWriter, object);
        }
        else if (typeof object === "symbol") {
            return await this.encodeSymbol(valueWriter, object); // EXT
        }
        else {
            // if (typeof object === "object")
            const ext = await this.extensionCodec.tryToEncodeAsync(object, this, this.context);
            if (ext != null) {
                return await this.encodeExtension(valueWriter, ext); //EXT
            }
            else if (Array.isArray(object)) {
                return await this.encodeArray(valueWriter, object, this.depth);
            }
            else if (object instanceof Map) {
                return await this.encodeMap(valueWriter, object, this.depth); // EXT
            }
            else if (object instanceof Set) {
                return await this.encodeSet(valueWriter, object, this.depth); // EXT
            }
            else if (object instanceof RegExp) {
                return await this.encodeRegEx(valueWriter, object); // EXT
            }
            else if (ArrayBuffer.isView(object) || object instanceof Buffer) {
                return await this.encodeBinary(valueWriter, object); // EXT
            }
            else if (object instanceof Date) {
                return await this.encodeDate(valueWriter, object); // EXT
            }
            else if (typeof object === "object") {
                return await this.encodeObject(valueWriter, object, this.depth);
            }
            else {
                // function and other special object come here unless extensionCodec handles them.
                this.throwError(`Unrecognized object: ${Object.prototype.toString.apply(object)} ` + this.fileName);
            }
        }
        return;
    }
    ;
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
    async encodeObject(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        var length = 1;
        const keys = Object.keys(object);
        const size = keys.length;
        if (size < 16) {
            // fixmap
            await valueWriter.ubyte(exports.JPType.OBJECT_0 + size);
        }
        else if (size < 0x100) {
            // map 8
            await valueWriter.ubyte(exports.JPType.OBJECT8);
            await valueWriter.ubyte(size);
            length++;
        }
        else if (size < 0x10000) {
            // map 16
            await valueWriter.ubyte(exports.JPType.OBJECT16);
            await valueWriter.ushort(size);
            length += 2;
        }
        else if (size < 0x100000000) {
            // map 32
            await valueWriter.ubyte(exports.JPType.OBJECT32);
            await valueWriter.uint32(size);
            length += 4;
        }
        else {
            this.throwError(`Too large map object: ${size} in file ` + this.fileName);
        }
        for (const key of keys) {
            const value = object[key];
            length += await this.encodeString(valueWriter, key, true);
            length += await this.doEncode(valueWriter, value, depth + 1);
        }
        return length;
    }
    ;
    /**
     * Writes an `Array` to the buffer as `Array<unknown>`
     *
     * @param valueWriter - Writer
     * @param array - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    async encodeArray(valueWriter, array, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        var length = 1;
        const size = array.length;
        if (size < 16) {
            // fixarray
            await valueWriter.ubyte(exports.JPType.ARRAY_0 + size);
        }
        else if (size < 0x100) {
            // uint8
            await valueWriter.ubyte(exports.JPType.ARRAY8);
            await valueWriter.ubyte(size);
            length++;
        }
        else if (size < 0x10000) {
            // array 16
            await valueWriter.ubyte(exports.JPType.ARRAY16);
            await valueWriter.ushort(size);
            length += 2;
        }
        else if (size < 0x100000000) {
            // array 32
            await valueWriter.ubyte(exports.JPType.ARRAY32);
            await valueWriter.uint32(size);
            length += 4;
        }
        else {
            this.throwError(`Too large array: ${size} in file ` + this.fileName);
        }
        for (const item of array) {
            length += await this.doEncode(valueWriter, item, depth + 1);
        }
        return length;
    }
    ;
    /**
     * Writes a `string` to the buffer's string section.
     *
     * @param valueWriter - Writer
     * @param string - Data to encode
     * @param isKey If the string is used a an Object key. Only used when `stripKeys` is enabled.
     * @returns The `number` of bytes written
     */
    async encodeString(valueWriter, string, isKey) {
        if (isKey == undefined) {
            isKey = false;
        }
        var length = 1;
        if (isKey && this.KeyStripped) {
            const index = this.keyList.add(string);
            if (index < 16) {
                await valueWriter.ubyte(exports.JPType.KEY_0 + index);
            }
            else if (index < 0x100) {
                // uint8
                await valueWriter.ubyte(exports.JPType.KEY8);
                await valueWriter.ubyte(index);
                length++;
            }
            else if (index < 0x10000) {
                // unit16
                await valueWriter.ubyte(exports.JPType.KEY16);
                await valueWriter.ushort(index);
                length += 2;
            }
            else if (index < 0x100000000) {
                // unit32
                await valueWriter.ubyte(exports.JPType.KEY32);
                await valueWriter.uint32(index);
                length += 4;
            }
            else {
                this.throwError(`String index too long: ${index} in file ` + this.fileName);
            }
        }
        else {
            const index = this.stringList.add(string);
            if (index < 16) {
                await valueWriter.ubyte(exports.JPType.STR_0 + index);
            }
            else if (index < 0x100) {
                // uint8
                await valueWriter.ubyte(exports.JPType.STR8);
                await valueWriter.ubyte(index);
                length++;
            }
            else if (index < 0x10000) {
                // unit16
                await valueWriter.ubyte(exports.JPType.STR16);
                await valueWriter.ushort(index);
                length += 2;
            }
            else if (index < 0x100000000) {
                // unit32
                await valueWriter.ubyte(exports.JPType.STR32);
                await valueWriter.uint32(index);
                length += 4;
            }
            else {
                this.throwError(`String index too long: ${index} in file ` + this.fileName);
            }
        }
        return length;
    }
    ;
    /**
     * Writes a `null` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeNull(valueWriter) {
        await valueWriter.ubyte(exports.JPType.NULL);
        return 1;
    }
    ;
    /**
     * Writes an `undefined` to the buffer
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeUndefined(valueWriter) {
        await valueWriter.ubyte(exports.JPType.UNDEFINED);
        return 1;
    }
    ;
    /**
     * Writes a `boolean` true or false to the buffer
     *
     * @param valueWriter - Writer
     * @param object - `true` or `false`
     * @returns The `number` of bytes written
     */
    async encodeBoolean(valueWriter, object) {
        if (object === false) {
            await valueWriter.ubyte(exports.JPType.BOOL_FALSE);
        }
        else {
            await valueWriter.ubyte(exports.JPType.BOOL_TRUE);
        }
        return 1;
    }
    ;
    /**
     * Writes an "finished" byte to the buffer. End the loop when hit if not finished otherwise.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeFinished(valueWriter) {
        await valueWriter.ubyte(exports.JPType.FINISHED);
        return 1;
    }
    ;
    /**
     * Writes a "list end" byte to the buffer, useful when pulling loose data and don't want to break the whole loop.
     *
     * @param valueWriter - Writer
     * @returns The `number` of bytes written
     */
    async encodeListEnd(valueWriter) {
        await valueWriter.ubyte(exports.JPType.LIST_END);
        return 1;
    }
    ;
    /**
     * Writes a `number` to the buffer . Computes the right byte size base on value.
     *
     * Notes: Use `encodeBigInt64` for `bigint` types.
     *
     * @param valueWriter - Writer
     * @param number - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeNumber(valueWriter, number) {
        var length = 1;
        if (Number.isSafeInteger(number)) {
            if (number >= 0) {
                if (number < 0x80) {
                    // positive fixint
                    await valueWriter.ubyte(number);
                }
                else if (number < 0x100) {
                    // uint 8
                    await valueWriter.ubyte(exports.JPType.UINT_8);
                    await valueWriter.ubyte(number);
                    length++;
                }
                else if (number < 0x10000) {
                    // uint 16
                    await valueWriter.ubyte(exports.JPType.UINT_16);
                    await valueWriter.ushort(number);
                    length += 2;
                }
                else if (number < 0x100000000) {
                    // uint 32
                    await valueWriter.ubyte(exports.JPType.UINT_32);
                    await valueWriter.uint32(number);
                    length += 4;
                }
                else {
                    // uint 64
                    await valueWriter.ubyte(exports.JPType.UINT_64);
                    await valueWriter.uint64(number);
                    length += 8;
                }
            }
            else {
                if (number >= -32) {
                    // negative fixint
                    await valueWriter.byte(number);
                }
                else if (number >= -128) {
                    // int 8
                    await valueWriter.ubyte(exports.JPType.INT_8);
                    await valueWriter.byte(number);
                    length++;
                }
                else if (number >= -32768) {
                    // int 16
                    await valueWriter.ubyte(exports.JPType.INT_16);
                    await valueWriter.int16(number);
                    length += 2;
                }
                else if (number >= -2147483648) {
                    // int 32
                    await valueWriter.ubyte(exports.JPType.INT_32);
                    await valueWriter.int32(number);
                    length += 4;
                }
                else {
                    // int 64
                    await valueWriter.ubyte(exports.JPType.INT_64);
                    await valueWriter.int64(number);
                    length += 8;
                }
            }
            return length;
        }
        else {
            return await this.encodeNumberAsFloat(valueWriter, number);
        }
    }
    ;
    /**
     * Writes a `bigint` to the buffer. Always written as a 64 bit value.
     *
     * @param valueWriter - Writer
     * @param bigint - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeBigInt64(valueWriter, bigint) {
        var length = 0;
        if (bigint >= BigInt(0)) {
            // uint 64
            await valueWriter.ubyte(exports.JPType.UINT_64);
            length++;
            await valueWriter.uint64(bigint);
            length += 8;
        }
        else {
            // int 64
            await valueWriter.ubyte(exports.JPType.INT_64);
            length++;
            await valueWriter.int64(bigint);
            length += 8;
        }
        return length;
    }
    ;
    async encodeStringHeader(byteLength) {
        var length = 1;
        if (this.strWriterAsync == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }
        if (byteLength < 16) {
            // fixstr
            await this.strWriterAsync.ubyte(exports.JPType.STR_0 + byteLength);
        }
        else if (byteLength < 0x100) {
            // str 8
            await this.strWriterAsync.ubyte(exports.JPType.STR8);
            await this.strWriterAsync.ubyte(byteLength);
            length++;
        }
        else if (byteLength < 0x10000) {
            // str 16
            await this.strWriterAsync.ubyte(exports.JPType.STR16);
            await this.strWriterAsync.uint16(byteLength);
            length += 2;
        }
        else if (byteLength < 0x100000000) {
            // str 32
            await this.strWriterAsync.ubyte(exports.JPType.STR32);
            await this.strWriterAsync.uint32(byteLength);
            length += 4;
        }
        else {
            this.throwError(`Too long string: ${byteLength} bytes in UTF-8 in file ` + this.fileName);
        }
        return length;
    }
    ;
    async writeString(object) {
        if (this.strWriterAsync == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }
        const encoder = new TextEncoder();
        const encodedString = encoder.encode(object);
        const byteLength = encodedString.length;
        var length = await this.encodeStringHeader(byteLength);
        await this.strWriterAsync.string(object, { length: byteLength });
        return length + byteLength;
    }
    ;
    async writeStringsData() {
        const array = this.stringList.getValues();
        const size = array.length;
        if (this.strWriterAsync == null) {
            this.throwError(" Didn't create writer. " + this.fileName);
        }
        if (size < 16) {
            // fixarray
            await this.strWriterAsync.ubyte(exports.JPType.ARRAY_0 + size);
        }
        else if (size < 0x100) {
            // uint8
            await this.strWriterAsync.ubyte(exports.JPType.ARRAY8);
            await this.strWriterAsync.ubyte(size);
        }
        else if (size < 0x10000) {
            // array 16
            await this.strWriterAsync.ubyte(exports.JPType.ARRAY16);
            await this.strWriterAsync.ushort(size);
        }
        else if (size < 0x100000000) {
            // array 32
            await this.strWriterAsync.ubyte(exports.JPType.ARRAY32);
            await this.strWriterAsync.uint32(size);
        }
        else {
            this.throwError(`String array too large: ${size} in file ` + this.fileName);
        }
        for (let i = 0; i < size; i++) {
            const el = array[i];
            await this.writeString(el);
        }
    }
    ;
    async encodeNumberAsFloat(valueWriter, object) {
        var length = 1;
        if (isFloat32Safe(object)) {
            // float 32
            await valueWriter.ubyte(exports.JPType.FLOAT32);
            await valueWriter.float(object);
            length += 4;
        }
        else {
            // float 64
            await valueWriter.ubyte(exports.JPType.FLOAT64);
            await valueWriter.dfloat(object);
            length += 8;
        }
        return length;
    }
    ;
    ////////////
    //  EXTS  //
    ////////////
    async encodeExtension(valueWriter, ext) {
        const size = ext.data.length;
        var length = size;
        if (size < 0x100) {
            // ext 8
            await valueWriter.ubyte(exports.JPType.EXT8);
            await valueWriter.ubyte(size);
            length += 2;
        }
        else if (size < 0x10000) {
            // ext 16
            await valueWriter.ubyte(exports.JPType.EXT16);
            await valueWriter.ushort(size);
            length += 3;
        }
        else if (size < 0x100000000) {
            // ext 32
            await valueWriter.ubyte(exports.JPType.EXT32);
            await valueWriter.uint32(size);
            length += 5;
        }
        else {
            this.throwError(`Too large extension object: ${size} in file ` + this.fileName);
        }
        await valueWriter.ubyte(ext.type);
        length++;
        await valueWriter.overwrite(ext.data, valueWriter.offset, true);
        return length;
    }
    ;
    /**
     * Writes a `Map` to the buffer as `Map<key, value>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    async encodeMap(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        // Note: length here is the array size of Map, not the buffer size
        var length = 1;
        const keys = [...object.keys()];
        const size = object.size;
        if (size < 0x100) {
            await valueWriter.ubyte(exports.JPType.EXT8);
            await valueWriter.ubyte(size);
            length++;
        }
        else if (size < 0x10000) {
            await valueWriter.ubyte(exports.JPType.EXT16);
            await valueWriter.ushort(size);
            length += 2;
        }
        else if (size < 0x100000000) {
            await valueWriter.ubyte(exports.JPType.EXT32);
            await valueWriter.uint32(size);
            length += 4;
        }
        else {
            this.throwError(`Too large Set length: ${size} in file ` + this.fileName);
        }
        await this.valueWriterAsync.ubyte(exports.JPExtType.Maps);
        length++;
        for (const key of keys) {
            const value = object.get(key);
            length += await this.doEncode(valueWriter, key, depth + 1); // keys can have any type here
            //this.valueWriter.ubyte = JPType.LIST_END; length++;
            length += await this.doEncode(valueWriter, value, depth + 1);
            //this.valueWriter.ubyte = JPType.LIST_END; length++;
        }
        return length;
    }
    ;
    /**
     * Writes a `Set` to the buffer as `Set<type>`
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @param depth - Level depth within the master object. Leave blank unless you have a reason for adding to running loop.
     * @returns The `number` of bytes written
     */
    async encodeSet(valueWriter, object, depth) {
        if (depth == undefined) {
            depth = this.depth;
        }
        // Note: length here is the array size of Set, not the buffer size
        var length = 1;
        const size = object.size;
        if (size < 0x100) {
            await valueWriter.ubyte(exports.JPType.EXT8);
            await valueWriter.ubyte(size);
            length++;
        }
        else if (size < 0x10000) {
            await valueWriter.ubyte(exports.JPType.EXT16);
            await valueWriter.ushort(size);
            length += 2;
        }
        else if (size < 0x100000000) {
            await valueWriter.ubyte(exports.JPType.EXT32);
            await valueWriter.uint32(size);
            length += 4;
        }
        else {
            this.throwError(`Too large Set length: ${size} in file ` + this.fileName);
        }
        await this.valueWriterAsync.ubyte(exports.JPExtType.Sets);
        for (const item of object) {
            length += await this.doEncode(valueWriter, item, depth + 1);
            // this.valueWriter.ubyte = JPType.LIST_END; length++;
        }
        return length;
    }
    ;
    /**
     * Writes a `symbol` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeSymbol(valueWriter, object) {
        const extBuffer = new BiWriterAsync(Buffer.alloc(512));
        const keyCheck = Symbol.keyFor(object);
        const global = !!keyCheck;
        var key = keyCheck ?? object.description;
        key = key ?? "";
        var length = 0;
        length += await this.encodeBoolean(extBuffer, global);
        length += await this.encodeString(extBuffer, key, false);
        await extBuffer.trim();
        if (length < 0x100) {
            await valueWriter.ubyte(exports.JPType.EXT8);
            await valueWriter.ubyte(length);
        }
        else if (length < 0x10000) {
            await valueWriter.ubyte(exports.JPType.EXT16);
            await valueWriter.ushort(length);
        }
        else if (length < 0x100000000) {
            await valueWriter.ubyte(exports.JPType.EXT32);
            await valueWriter.uint(length);
        }
        else {
            this.throwError(`Too large Symbol length: ${length} in file ` + this.fileName);
        }
        await valueWriter.ubyte(exports.JPExtType.Symbol);
        const data = await extBuffer.getData();
        await valueWriter.overwrite(data, valueWriter.offset, true);
        return length;
    }
    ;
    /**
     * Writes a `RegEx` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeRegEx(valueWriter, object) {
        const extBuffer = new BiWriterAsync(Buffer.alloc(512), { growthIncrement: this.growthIncrement });
        const src = object.source;
        const flags = object.flags;
        var length = 0;
        length += await this.encodeString(extBuffer, src, false);
        length += await this.encodeString(extBuffer, flags, false);
        await extBuffer.trim();
        if (length < 0x100) {
            await valueWriter.ubyte(exports.JPType.EXT8);
            await valueWriter.ubyte(length);
        }
        else if (length < 0x10000) {
            await valueWriter.ubyte(exports.JPType.EXT16);
            await valueWriter.ushort(length);
        }
        else if (length < 0x100000000) {
            await valueWriter.ubyte(exports.JPType.EXT32);
            await valueWriter.uint(length);
        }
        else {
            this.throwError(`Too large RegEx length: ${length} in file ` + this.fileName);
        }
        await valueWriter.ubyte(exports.JPExtType.RegEx);
        const data = await extBuffer.getData();
        await valueWriter.writeUBytes(data, true);
        return length;
    }
    ;
    /**
     * Writes a `TypedArray` or `Buffer` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeBinary(valueWriter, object) {
        var length = 1;
        const byteLength = object.byteLength;
        if (byteLength < 0x100) {
            await valueWriter.ubyte(exports.JPType.EXT8);
            await valueWriter.ubyte(byteLength);
            length++;
        }
        else if (byteLength < 0x10000) {
            await valueWriter.ubyte(exports.JPType.EXT16);
            await valueWriter.ushort(byteLength);
            length += 2;
        }
        else if (byteLength < 0x100000000) {
            await valueWriter.ubyte(exports.JPType.EXT32);
            await valueWriter.uint32(byteLength);
            length += 4;
        }
        else {
            this.throwError(`Buffer ranged too large. ${byteLength} in file ` + this.fileName);
        }
        if (object instanceof Buffer) {
            await valueWriter.ubyte(exports.JPExtType.Buffer);
            length++;
            await valueWriter.overwrite(object, valueWriter.offset, true);
            length += object.length;
        }
        else {
            if (object instanceof Int8Array) {
                await valueWriter.ubyte(exports.JPExtType.Int8Array);
            }
            else if (object instanceof Uint8Array) {
                await valueWriter.ubyte(exports.JPExtType.Uint8Array);
            }
            else if (object instanceof Uint8ClampedArray) {
                await valueWriter.ubyte(exports.JPExtType.Uint8ClampedArray);
            }
            else if (object instanceof Int16Array) {
                await valueWriter.ubyte(exports.JPExtType.Int16Array);
            }
            else if (object instanceof Uint16Array) {
                await valueWriter.ubyte(exports.JPExtType.Uint16Array);
            }
            else if (object instanceof Int32Array) {
                await valueWriter.ubyte(exports.JPExtType.Int32Array);
            }
            else if (object instanceof Uint32Array) {
                await valueWriter.ubyte(exports.JPExtType.Uint32Array);
            }
            else if (object instanceof Float32Array) {
                await valueWriter.ubyte(exports.JPExtType.Float32Array);
            }
            else if (object instanceof Float64Array) {
                await valueWriter.ubyte(exports.JPExtType.Float64Array);
            }
            else if (object instanceof BigInt64Array) {
                await valueWriter.ubyte(exports.JPExtType.BigInt64Array);
            }
            else if (object instanceof BigUint64Array) {
                await valueWriter.ubyte(exports.JPExtType.BigUint64Array);
                // @ts-ignore
            }
            else if (object instanceof Float16Array) {
                await valueWriter.ubyte(exports.JPExtType.Float16Array);
            }
            else {
                this.throwError(' Unknown Buffer type in file ' + this.fileName);
            }
            length++;
            const uData = new Uint8Array(object.buffer);
            await valueWriter.overwrite(uData, valueWriter.offset, true);
            length += uData.length;
        }
        return length;
    }
    ;
    /**
     * Writes a `Date` to the buffer
     *
     * @param valueWriter - Writer
     * @param object - Data to encode
     * @returns The `number` of bytes written
     */
    async encodeDate(valueWriter, object) {
        const TIMESTAMP32_MAX_SEC = 0x100000000 - 1; // 32-bit unsigned int
        const TIMESTAMP64_MAX_SEC = 0x400000000 - 1; // 34-bit unsigned int
        const msec = object.getTime();
        const _sec = Math.floor(msec / 1e3);
        const _nsec = (msec - _sec * 1e3) * 1e6;
        // Normalizes { sec, nsec } to ensure nsec is unsigned.
        const nsecInSec = Math.floor(_nsec / 1e9);
        const sec = _sec + nsecInSec;
        const nsec = _nsec - nsecInSec * 1e9;
        await valueWriter.ubyte(exports.JPType.EXT8);
        if (sec >= 0 && nsec >= 0 && sec <= TIMESTAMP64_MAX_SEC) {
            // Here sec >= 0 && nsec >= 0
            if (nsec === 0 && sec <= TIMESTAMP32_MAX_SEC) {
                // timestamp 32 = { sec32 (unsigned) }
                await valueWriter.ubyte(4);
                await valueWriter.ubyte(exports.JPExtType.Date);
                await valueWriter.uint32(sec >>> 0);
                return 7;
            }
            else {
                await valueWriter.ubyte(8);
                await valueWriter.ubyte(exports.JPExtType.Date);
                // timestamp 64 = { nsec30 (unsigned), sec34 (unsigned) }
                const secHigh = sec / 0x100000000;
                const secLow = sec & 0xffffffff;
                // nsec30 | secHigh2
                await valueWriter.uint32(((nsec << 2) | (secHigh & 0x3)) >>> 0);
                // secLow32
                await valueWriter.uint32(secLow >>> 0);
                return 11;
            }
        }
        else {
            // timestamp 96 = { nsec32 (unsigned), sec64 (signed) }
            await valueWriter.ubyte(12);
            await valueWriter.ubyte(exports.JPExtType.Date);
            await valueWriter.uint32(nsec >>> 0);
            await valueWriter.int64(sec);
            return 15;
        }
    }
    ;
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
    async buildHeader(endian) {
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
        if (this.Encrypted == 0)
            this.EncryptionExcluded = 0;
        await bw.bit1(this.EncryptionExcluded);
        await bw.bit1(this.KeyStripped);
        await bw.bit1(0); // FLAG6
        await bw.bit1(0); // FLAG7
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
        this.headerBuffer = await bw.getData();
        return this.headerBuffer;
    }
    ;
    async finalizeBuffers() {
        if (this.strWriterAsync == null || this.valueWriterAsync == null) {
            this.throwError(" Didn't create writers. " + this.fileName);
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
    }
    ;
    /**
     * Can stip or include the key value in file
     *
     * Can also set your own key.
     *
     * @param {boolean?} EncryptionExcluded - remove key from file
     * @param {number?} Encryptionkey - 32 bit number
     */
    async encrypt(EncryptionExcluded, Encryptionkey) {
        this.Encrypted = 1;
        this.EncryptionExcluded = EncryptionExcluded ? 1 : 0;
        if (this.compWriterAsync == null) {
            this.throwError("Writer not created for encryption. " + this.fileName);
        }
        const cypter = new Crypt(Encryptionkey);
        this.encryptionKey = cypter.key;
        const srcData = await this.compWriterAsync.getData();
        const cryptBuffer = cypter.encrypt(srcData);
        await this.compWriterAsync.close();
        await this.compWriterAsync.open();
        await this.compWriterAsync.overwrite(cryptBuffer, 0, true);
        await this.compWriterAsync.trim();
        return this.compWriterAsync.size;
    }
    ;
    /**
     * Compresses data
     */
    async compress() {
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
    }
    ;
    /**
     * Creates CRC hash
     */
    async CRC() {
        this.Crc32 = 1;
        if (this.compWriterAsync == null) {
            this.throwError(" Writer not created for CRC. " + this.fileName);
        }
        const data = await this.compWriterAsync.getData();
        this.CRC32 = CRC32(data, 0) >>> 0;
        return;
    }
    ;
}

exports.JPDecode = JPDecode;
exports.JPDecodeAsync = JPDecodeAsync;
exports.JPEncode = JPEncode;
exports.JPEncodeAsync = JPEncodeAsync;
exports.JPExtData = JPExtData;
exports.JPExtensionCodec = JPExtensionCodec;
//# sourceMappingURL=index.cjs.js.map
