/*
Copyright 2022 Lukas Käppeli
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

import * as tlspl from "../src/tlspl";

describe("TLS presentation language", () => {
    it("should encode", () => {
        expect(tlspl.encode([
            tlspl.uint8(1),
            tlspl.uint16(512),
            tlspl.opaque(Uint8Array.from([9, 8, 7])),
            tlspl.variableOpaque(Uint8Array.from([6, 5, 4]), 2),
        ])).toEqual(Uint8Array.from([
            1,
            2, 0,
            9, 8, 7,
            0, 3, 6, 5, 4,
        ]));
        expect(tlspl.encode([
            tlspl.vector(
                [
                    tlspl.variableOpaque(Uint8Array.from([1]), 1),
                    tlspl.variableOpaque(Uint8Array.from([2, 3]), 1),
                    tlspl.variableOpaque(Uint8Array.from([4, 5, 6]), 1),
                ],
                1,
            ),
        ])).toEqual(Uint8Array.from([
            9,
            1, 1,
            2, 2, 3,
            3, 4, 5, 6,
        ]));
    });
    it("should decode", () => {
        expect(tlspl.decode(
            [
                tlspl.decodeUint8,
                tlspl.decodeUint16,
                tlspl.decodeOpaque(3),
                tlspl.decodeVariableOpaque(2),
            ],
            Uint8Array.from([
                1,
                2, 0,
                9, 8, 7,
                0, 3, 6, 5, 4,
            ]),
        )).toEqual([[1, 512, Uint8Array.from([9, 8, 7]), Uint8Array.from([6, 5, 4])], 11]);
        expect(tlspl.decode(
            [
                tlspl.decodeVector(tlspl.decodeVariableOpaque(1), 1),
            ],
            Uint8Array.from([
                9,
                1, 1,
                2, 2, 3,
                3, 4, 5, 6,
            ]),
        )).toEqual([[[Uint8Array.from([1]), Uint8Array.from([2, 3]), Uint8Array.from([4, 5, 6])]], 10]);
    });

    it("should encode and decode 64 bit ints", () => {
        const large_number = 1644235681557

        let uint64Encoded = tlspl.encode([tlspl.uint64(large_number)])
        let [decoded, _] = tlspl.decodeUint64(uint64Encoded, 0)

        expect(decoded).toEqual(large_number)
    })

});
