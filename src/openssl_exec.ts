import { spawn } from "node:child_process";

export function opensslSignAsync({
	content,
	priv_key
}: {
	content: string;
	/** private key file path */
	priv_key: string;
}): Promise<string> {
	return new Promise((resolve, reject) => {
		const child = spawn("openssl", [
			'dgst', '-sha256', '-hex', '-sign', priv_key
		]);

		let stdout = "";
		let stderr = "";
		child.stdout.on("data", (chunk) => stdout += chunk.toString());
		child.stderr.on("data", (chunk) => stderr += chunk.toString());

		child.on('error', () => reject(stderr));

		child.on("close", (code) => {
			if (code === 0) {
				resolve(stdout.trim());
			} else {
				reject(stderr);
			}
		});

		if (content && typeof content === "string" && content.length > 0) {
			child.stdin.write(content);
			child.stdin.end();
		}
	});
}
