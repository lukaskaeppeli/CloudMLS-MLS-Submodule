/*
Copyright 2020 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/** Encode things using TLS presentation language from
 * https://tools.ietf.org/html/rfc8446#section-3
 */

export interface Encoder {
    readonly length: number;
    writeToBuffer: ((buffer: Uint8Array, offset: number) => void);
}

export class Static implements Encoder {
    constructor(private readonly buffer: Uint8Array) {}
    get length(): number {
        return this.buffer.byteLength;
    }
    writeToBuffer(buffer: Uint8Array, offset: number): void {
        buffer.set(this.buffer, offset);
    }
}

export function uint8(num: number): Encoder {
    return {
        length: 1,
        writeToBuffer(buffer: Uint8Array, offset: number): void {
            buffer[offset] = num;
        },
    };
}

export function uint16(num: number): Encoder {
    return {
        length: 2,
        writeToBuffer(buffer: Uint8Array, offset: number): void {
            (new DataView(buffer.buffer)).setUint16(offset, num);
        },
    };
}

export function uint24(num: number): Encoder {
    return new Static(Uint8Array.of(num >> 16 & 0xff, num >> 8 & 0xff, num & 0xff));
}

export function uint32(num: number): Encoder {
    return {
        length: 4,
        writeToBuffer(buffer: Uint8Array, offset: number): void {
            (new DataView(buffer.buffer)).setUint32(offset, num);
        },
    };
}

export function uint64(num: number): Encoder {
    return {
        length: 8,
        writeToBuffer(buffer: Uint8Array, offset: number): void {
            const view: DataView = new DataView(buffer.buffer);
            view.setUint32(offset, num & 0xffffffff);
            view.setUint32(offset + 4, num >> 32 & 0xffffffff);
        },
    };
}

export function opaque(src: Uint8Array): Encoder {
    return new Static(src);
}

export function variableOpaque(src: Uint8Array, lengthBytes: number): Encoder {
    if (![1, 2, 4, 8].includes(lengthBytes)) {
        throw new Error("Invalid size for length");
    }
    return {
        length: lengthBytes + src.length,
        writeToBuffer(buffer: Uint8Array, offset: number): void {
            switch (lengthBytes) {
                case 1:
                    buffer[offset] = src.length;
                    break;
                case 2:
                    (new DataView(buffer.buffer).setUint16(offset, src.length));
                    break;
                case 4:
                    (new DataView(buffer.buffer).setUint32(offset, src.length));
                    break;
                case 8: {
                    const view: DataView = new DataView(buffer.buffer);
                    view.setUint32(offset, src.length >> 32 & 0xffffffff);
                    view.setUint32(offset + 4, src.length & 0xffffffff);
                    break;
                }
            }
            buffer.set(src, offset + lengthBytes);
        },
    };
}

// a struct is a concatenation of the fields
export function struct(items: Encoder[]): Encoder {
    const length: number = items.reduce(
        (acc, item) => acc + item.length,
        0,
    );
    return {
        length,
        writeToBuffer(buffer: Uint8Array, offset: number): void {
            let pos = offset;
            for (const item of items) {
                item.writeToBuffer(buffer, pos);
                pos += item.length;
            }
        },
    }
}

// a vector is the total length of items, followed by each item
export function vector(items: Encoder[], lengthBytes: number): Encoder {
    if (![1, 2, 4, 8].includes(lengthBytes)) {
        throw new Error("Invalid size for length");
    }
    const length: number = items.reduce(
        (acc, item) => acc + item.length,
        0,
    );
    const lengthEncoder =
        lengthBytes === 1 ? uint8(length) :
        lengthBytes === 2 ? uint16(length) :
        lengthBytes === 4 ? uint32(length) :
        uint64(length);
    return struct([lengthEncoder].concat(items));
}

export function encode(items: Encoder[]): Uint8Array {
    const length: number = items.reduce(
        (acc, item) => acc + item.length,
        0,
    );
    const out: Uint8Array = new Uint8Array(length);
    let pos = 0;
    for (const item of items) {
        item.writeToBuffer(out, pos);
        pos += item.length;
    }
    return out;
}

type Decoder = ((buffer: Uint8Array, offset: number) => [any, number]);

export function decodeUint8(buffer: Uint8Array, offset: number): [number, number] {
    return [buffer[offset], 1];
}

export function decodeUint16(buffer: Uint8Array, offset: number): [number, number] {
    return [(new DataView(buffer.buffer)).getUint16(offset), 2];
}

export function decodeUint32(buffer: Uint8Array, offset: number): [number, number] {
    return [(new DataView(buffer.buffer)).getUint32(offset), 4];
}

export function decodeUint64(buffer: Uint8Array, offset: number): [number, number] {
    const view: DataView = new DataView(buffer.buffer);
    return [view.getUint32(offset) << 32 | view.getUint32(offset + 4), 8];
}

export function decodeOpaque(length: number): Decoder {
    return (buffer: Uint8Array, offset: number): [Uint8Array, number] => {
        return [buffer.subarray(offset, offset + length), length];
    };
}

export function decodeVariableOpaque(lengthBytes: number): Decoder {
    if (![1, 2, 4, 8].includes(lengthBytes)) {
        throw new Error("Invalid size for length");
    }
    return (buffer: Uint8Array, offset: number): [Uint8Array, number] => {
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [length, ]: [any, number] =
            lengthBytes == 1 ? decodeUint8(buffer, offset) :
            lengthBytes == 2 ? decodeUint16(buffer, offset) :
            lengthBytes == 4 ? decodeUint32(buffer, offset) :
            decodeUint64(buffer, offset);
        return [buffer.subarray(offset + lengthBytes, offset + lengthBytes + length), lengthBytes + length];
    };
}

export function decodeStruct(decoders: Decoder[]): Decoder {
    return (buffer: Uint8Array, offset: number): [any[], number] => {
        const values: any[] = [];
        for (const decoder of decoders) {
            const [val, length]: [any, number] = decoder(buffer, offset);
            values.push(val);
            offset += length;
        }
        return [values, offset]
    }
}

export function decodeVector(decoder: Decoder, lengthBytes: number, numElems?: number): Decoder {
    if (![1, 2, 4, 8].includes(lengthBytes)) {
        throw new Error("Invalid size for length");
    }
    return (buffer: Uint8Array, offset: number): [any[], number] => {
        // eslint-disable-next-line comma-dangle, array-bracket-spacing
        const [length, ]: [any, number] =
            lengthBytes == 1 ? decodeUint8(buffer, offset) :
            lengthBytes == 2 ? decodeUint16(buffer, offset) :
            lengthBytes == 4 ? decodeUint32(buffer, offset) :
            decodeUint64(buffer, offset);
        const vec = [];
        let vecOffset = 0;
        while (vecOffset < length) {
            const [elem, elemLength] = decoder(buffer, vecOffset + lengthBytes);
            vec.push(elem);
            vecOffset += elemLength;
        }
        if (vecOffset !== length) {
            throw new Error("Claimed vector size does not match actual size");
        }
        if (numElems !== undefined && vec.length !== numElems) {
            throw new Error("Wrong number of elements");
        }
        return [vec, offset + lengthBytes + length];
    }
}

export function decode(
    decoders: Decoder[], buffer: Uint8Array, offset = 0,
): [any[], number] {
    const values: any[] = [];
    for (const decoder of decoders) {
        const [val, length]: [any, number] = decoder(buffer, offset);
        values.push(val);
        offset += length;
    }
    return [values, offset]
}
