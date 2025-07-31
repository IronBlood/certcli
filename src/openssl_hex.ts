const OPENSSL_HEX = /^(?:SHA2-256\(stdin\)=\s+|\(stdin\)=\s+)?([a-f0-9]{512,1024})$/;

export function extract_openssl_hex(hex: string) {
	const match = hex.trim().match(OPENSSL_HEX);
	return match ? match[1] : null;
}
