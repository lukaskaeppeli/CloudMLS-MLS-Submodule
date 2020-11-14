import {hkdfSha256} from "../src/hpke/hkdf";

describe("HKDF", () => {
    it("should HKDF with no salt/info", async () => {
        const ikm = Uint8Array.from([1, 2, 3]);
        const result = await hkdfSha256.expand(await hkdfSha256.extract(undefined, ikm), undefined, 64);
        const ikmKey = await window.crypto.subtle.importKey(
            "raw", ikm, "HKDF", false, ["deriveBits"],
        );
        expect(new Uint8Array(await window.crypto.subtle.deriveBits(
            {name: "HKDF", hash: "SHA-256", salt: new Uint8Array(32), info: new Uint8Array(0)},
            ikmKey, 64 * 8,
        ))).toEqual(result);
    });
    it("should HKDF with salt and info", async () => {
        const salt = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        const ikm = Uint8Array.from([1, 2, 3]);
        const info = Uint8Array.from([4, 5, 6, 7]);
        const result = await hkdfSha256.expand(await hkdfSha256.extract(salt, ikm), info, 64);
        const ikmKey = await window.crypto.subtle.importKey(
            "raw", ikm, "HKDF", false, ["deriveBits"],
        );
        expect(new Uint8Array(await window.crypto.subtle.deriveBits(
            {name: "HKDF", hash: "SHA-256", salt: salt, info: info},
            ikmKey, 64 * 8,
        ))).toEqual(result);
    });
});
