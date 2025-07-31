import { extract_openssl_hex } from "./openssl_hex";

describe("Extract openssl_hex", () => {
	const HEX = "1234".repeat(512 / 4);

	it("extracts hex when prefixed with '(stdin)= '", () => {
		const str = `(stdin)= ${HEX}`;
		expect(extract_openssl_hex(str)).toBe(HEX);
	});

	it("extracts hex when prefixed with 'SHA2-256(stdin)= '", () => {
		const str = `SHA2-256(stdin)=  ${HEX}`;
		expect(extract_openssl_hex(str)).toBe(HEX);
	});

	it("extracts raw hex when the input is exactly the hex blob", () => {
		expect(extract_openssl_hex(HEX)).toBe(HEX);
	});

	it("returns null when the prefix is unexpected", () => {
		expect(extract_openssl_hex(`foo ${HEX}`)).toBeNull();
	});
});
