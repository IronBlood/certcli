import crypto from "node:crypto";
import {
	fetch,
	ProxyAgent,
	setGlobalDispatcher,
} from "undici";
import {
	type AuthResponse,
	type Challenge,
	type DirectoryResponse,
	type OrderResponse,
	type FinalizeResponse,
	type ValidOrderResponse,
} from "./types";
import { extract_openssl_hex } from "./openssl_hex";

const FETCH_HEADERS = {
	"Content-Type": "application/jose+json",
};

function get_proxy(): undefined | string {
	for (let key of ["HTTPS_PROXY", "https_proxy"]) {
		if (process.env[key]) {
			return process.env[key];
		}
	}
	return undefined;
}

export const proxy_url: undefined | string = get_proxy();
if (proxy_url) {
	const agent = new ProxyAgent(proxy_url);
	setGlobalDispatcher(agent);
}

// always empty payload
const CHALLENGE_PAYLOAD = b64("{}");
const RECHECK_AUTH_PAYLOAD_B64 = "";
const RECHECK_ORDER_PAYLOAD_B64 = "";
const CERT_PAYLOAD_B64 = "";

const DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory";

async function sha256Async(bytes) {
	const hash = await crypto.subtle.digest("SHA-256", bytes);
	return new Uint8Array(hash);
}

/**
 * @param token the same as file-based content
 */
export async function gen_dnstoken(token: string) {
	const len = token.length,
		bytes = new Uint8Array(len);
	for (let i = 0; i < len; i++) {
		bytes[i] = token.charCodeAt(i);
	}
	const hash = await sha256Async(bytes);
	return b64(hash);
}

function b64(data) {
	return Buffer.from(data).toString("base64url");
}

function hex2b64(openssl_output: string) {
	let hex = extract_openssl_hex(openssl_output);
	if (hex === null) {
		return null;
	}

	var bytes: number[] = [];
	for (let i = 0; i < hex.length; i += 2) {
		bytes.push(parseInt(hex.substring(i, i + 2), 16));
	}
	return b64(new Uint8Array(bytes));
}

function cachebuster() {
	return "cachebuster=" + b64(crypto.getRandomValues(new Uint8Array(8)));
}

async function getNonceAsync(dir: DirectoryResponse) {
	const response = await fetch(`${dir.newNonce}?${cachebuster()}`);

	if (!response.ok)
		throw "Failed to fetch nonce from Let's Encrypt";

	return response.headers.get("Replay-Nonce");
}

export async function populateDirectoryAsync() {
	const res = await fetch(`${DIRECTORY_URL}?${cachebuster()}`)

	if (!res.ok) {
		console.log("❌ Error: Let's Encrypt appears to be down. Please try again later.");
		process.exit(1);
	}

	return res.json() as Promise<DirectoryResponse>;
}

interface Account {
	pubkey: string;
	alg: string;
	jwk: crypto.JsonWebKey;
	thumbprint: string;
	registration_payload_json: {
		termsOfServiceAgreed: boolean;
	};
	registration_payload_b64: string;
	update_payload_json: {
		contact: string[];
	};
	update_payload_b64: string;
}

export async function createAccountAsync({
	email,
	pubkey,
}: {
	email: string;
	pubkey: string;
}): Promise<Account> {
	// validate email
	const email_re = /^(([^<>()[\]\.,;:\s@\"]+(\.[^<>()[\]\.,;:\s@\"]+)*)|(\".+\"))@(([^<>()[\]\.,;:\s@\"]+\.)+[^<>()[\]\.,;:\s@\"]{2,})$/i;
	if (!email_re.test(email)) {
		throw "Account email doesn't look valid.";
	}

	// parse account public key
	if (pubkey === "") {
		throw "You need to include an account public key.";
	}

	const keyObj = crypto.createPublicKey(pubkey);
	const { e, kty, n } = keyObj.export({ format: "jwk" });
	const jwk = { e, kty, n };
	const jwk_json_str = JSON.stringify(jwk);
	const jwk_bytes = new Uint8Array(jwk_json_str.length);
	for (let i = 0; i < jwk_json_str.length; i++) {
		jwk_bytes[i] = jwk_json_str.charCodeAt(i);
	}

	const hash = await sha256Async(jwk_bytes);

	let registration_payload_json = {
		termsOfServiceAgreed: true,
	};
	let update_payload_json = {
		contact: [ "mailto:" + email ],
	};

	return {
		pubkey,
		alg: "RS256",
		jwk,
		thumbprint: b64(hash),
		registration_payload_json,
		registration_payload_b64: b64(JSON.stringify(registration_payload_json)),
		update_payload_json,
		update_payload_b64: b64(JSON.stringify(update_payload_json)),
	};
}

export function createOrder({
	domains,
}: {
	domains: string[];
}) {
	const order_payload_json = {
		identifiers: domains.map(value => ({
			type: "dns",
			value,
		})),
	};

	return {
		order_payload_json,
		order_payload_b64: b64(JSON.stringify(order_payload_json)),
	};
}

/**
 * Generate message to be signed by openssl
 */
export async function createOrderCmdAsync({
	directory,
	account,
}: {
	directory: DirectoryResponse;
	account: Account;
}) {
	const nonce = await getNonceAsync(directory);
	const registration_protected_json = {
		url: directory.newAccount,
		alg: account.alg,
		nonce,
		jwk: account.jwk,
	};
	const registration_protected_b64 = b64(JSON.stringify(registration_protected_json));

	return {
		registration_protected_b64,
		cmd: `${registration_protected_b64}.${account.registration_payload_b64}`,
	}
}

/**
 * Step: 3a
 */
export async function validateRegistrationAsync({
	account,
	directory,
	openssl_order_signature,
	registration_protected_b64,
}: {
	account: Account,
	directory: DirectoryResponse,
	openssl_order_signature: string;
	registration_protected_b64: string,
}) {
	const signature = hex2b64(openssl_order_signature);
	if (signature === null) {
		throw "null signature";
	}
	const response_newaccount = await fetch(directory.newAccount, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: registration_protected_b64,
			payload: account.registration_payload_b64,
			signature,
		}),
	});

	if (!([200, 201, 204].includes(response_newaccount.status))) {
		console.log(response_newaccount.status);
		console.log(await response_newaccount.json());
		throw "Account registration failed. Please start back at Step 1. ";
	}

	const account_uri = response_newaccount.headers.get("Location");
	if (!account_uri) {
		throw "account_uri not found";
	}

	const nonce = await getNonceAsync(directory);

	const update_protected_json = {
		url: account_uri,
		alg: account.alg,
		nonce,
		kid: account_uri,
	};
	const update_protected_b64 = b64(JSON.stringify(update_protected_json));

	return {
		account_uri,
		update_protected_b64,
		cmd: `${update_protected_b64}.${account.update_payload_b64}`
	};
}

// Step: 3b
export async function validateUpdateAsync({
	account,
	account_uri,
	directory,
	openssl_registration_signature,
	order,
	update_protected_b64,
}: {
	account: Account;
	account_uri: string;
	directory: DirectoryResponse;
	openssl_registration_signature: string;
	order: ReturnType<typeof createOrder>;
	update_protected_b64: string;
}) {
	const signature = hex2b64(openssl_registration_signature);
	const response = await fetch(account_uri, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: update_protected_b64,
			payload: account.update_payload_b64,
			signature,
		}),
	});

	if (response.status != 200) {
		throw "Account contact update failed. Please start back at Step 1.";
	}

	const nonce = await getNonceAsync(directory);

	const order_protected_json = {
		url: directory.newOrder,
		alg: account.alg,
		nonce,
		kid: account_uri,
	};

	const order_protected_b64 = b64(JSON.stringify(order_protected_json));

	return {
		order_protected_b64,
		cmd: `${order_protected_b64}.${order.order_payload_b64}`,
	};
}

/*
 * Step 3c: Create New Order (POST /newOrder)
 */
export async function validateOrderAsync({
	directory,
	openssl_validate_order_signature,
	order,
	order_protected_b64,
}: {
	directory: DirectoryResponse;
	openssl_validate_order_signature: string;
	order: ReturnType<typeof createOrder>;
	order_protected_b64: string;
}) {
	const signature = hex2b64(openssl_validate_order_signature);
	const response = await fetch(directory.newOrder, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: order_protected_b64,
			payload: order.order_payload_b64,
			signature,
		}),
	});

	if (!([200, 201].includes(response.status))) {
		const json = await response.json();
		console.log(response.status, json);
		throw "Order failed. Please start back at Step 1.";
	}

	const order_uri = response.headers.get("Location");
	if (!order_uri) {
		throw "order_uri not found";
	}
	const order_response = (await response.json()) as OrderResponse;

	return {
		order_uri,
		order_response,
	}
}

export async function buildAuthorizationAsync({
	idx,
	//status,
	directory,
	order_response,
	account,
	account_uri,
	auth_payload_b64,
}: {
	idx: number;
	//status: any;
	directory: DirectoryResponse;
	order_response: OrderResponse;
	account: Account;
	account_uri: string;
	auth_payload_b64: string;
}) {
	const auth_url = order_response.authorizations[idx];

	const nonce = await getNonceAsync(directory);
	const protected_json = {
		url: auth_url,
		alg: account.alg,
		nonce,
		kid: account_uri,
	};

	const protected_b64 = b64(JSON.stringify(protected_json));

	return {
		auth_url,
		auth_protected_json: protected_json,
		auth_protected_b64: protected_b64,
		cmd: `${protected_b64}.${auth_payload_b64}`,
	};
}

// 4b load challenges
export async function validateAuthorizationAsync({
	auth_url,
	auth_protected_b64,
	auth_payload_b64 = "", // To be checked, "" or "e30" (b64("{}"))
	openssl_auth_sig,
}: {
	auth_url: string;
	auth_protected_b64: string;
	auth_payload_b64?: string;
	openssl_auth_sig: string;
}) {
	const signature = hex2b64(openssl_auth_sig);
	const response = await fetch(auth_url, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: auth_protected_b64,
			payload: auth_payload_b64,
			signature,
		}),
	});

	if (response.status !== 200) {
		console.log(response.status);
		console.log(await response.json());
		throw "Loading challenges failed. Please start back at Step 1.";
	}

	const auth_obj = (await response.json()) as AuthResponse;

	return auth_obj;
}

// 4c
export async function confirmChallengeAsync({
	account,
	account_uri,
	challenge,
	directory,
}: {
	account: Account;
	account_uri: string;
	challenge: Challenge;
	directory: DirectoryResponse;
}) {
	const nonce = await getNonceAsync(directory);
	const protected_json = {
		url: challenge.url,
		alg: account.alg,
		nonce,
		kid: account_uri,
	};
	const challenge_protected_b64 = b64(JSON.stringify(protected_json));
	return {
		challenge_protected_b64,
		cmd: `${challenge_protected_b64}.${CHALLENGE_PAYLOAD}`,
	}
}

// 4d
export async function validateChallengeAsync({
	account,
	account_uri,
	challenge,
	challenge_protected_b64,
	directory,
	openssl_challenge_signature,
}: {
	account: Account;
	account_uri: string;
	challenge: Challenge;
	challenge_protected_b64: string;
	directory: DirectoryResponse;
	openssl_challenge_signature: string;
}) {
	const signature = hex2b64(openssl_challenge_signature);
	const response = await fetch(challenge.url, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: challenge_protected_b64,
			payload: CHALLENGE_PAYLOAD,
			signature,
		}),
	});

	if (response.status !== 200) {
		// TODO FIXME
		throw "Challenge submission failed. Please start back at Step 1.";
	}

	// @ts-ignore TODO check response
	const challenge_response = await response.json();
	const nonce = await getNonceAsync(directory);
	const recheck_auth_protected_json = {
		url: challenge.url,
		alg: account.alg,
		nonce,
		kid: account_uri,
	};
	const recheck_auth_protected_b64 = b64(JSON.stringify(recheck_auth_protected_json));
	return {
		recheck_auth_protected_b64,
		cmd: `${recheck_auth_protected_b64}.${RECHECK_AUTH_PAYLOAD_B64}`,
	};
}

// 4e
export async function checkAuthorizationAsync({
	account,
	account_uri,
	challenge,
	directory,
	openssl_validate_challenge_signature,
	recheck_auth_protected_b64,
}: {
	account: Account;
	account_uri: string;
	challenge: Challenge;
	directory: DirectoryResponse;
	openssl_validate_challenge_signature: string;
	recheck_auth_protected_b64: string;
}) {
	const signature = hex2b64(openssl_validate_challenge_signature);
	const response = await fetch(challenge.url, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: recheck_auth_protected_b64,
			payload: RECHECK_AUTH_PAYLOAD_B64,
			signature,
		}),
	});

	if (response.status !== 200) {
		console.log(response.status);
		console.log(await response.json());
		throw "Loading challenge status failed. Please start back at Step 1."
	}

	const auth_obj = (await response.json()) as AuthResponse;
	const status = auth_obj.status;

	if (status === "pending") {
		console.log(auth_obj);
		const nonce = await getNonceAsync(directory);
		const recheck_auth_protected_json = {
			url: challenge.url,
			alg: account.alg,
			nonce,
			kid: account_uri,
		};
		const recheck_auth_protected_b64 = b64(JSON.stringify(recheck_auth_protected_json));
		return {
			recheck_auth_protected_b64,
			cmd: `${recheck_auth_protected_b64}.${RECHECK_AUTH_PAYLOAD_B64}`,
		};
	} else if (status === "valid") {
		return {
			status,
		};
	} else {
		// @ts-ignore
		console.log(`\n${auth_obj.error.detail}`);
		console.log("Loading challenge status failed. Please start back at Step 1.");
		process.exit(1);
	}
}

export async function finalizeOrderAsync({
	account,
	account_uri,
	directory,
	order,
	pem,
}: {
	account: Account;
	account_uri: string;
	directory: DirectoryResponse;
	order: OrderResponse;
	pem: string;
}) {
	const nonce = await getNonceAsync(directory);
	const finalize_protected_json = {
		url: order.finalize,
		alg: account.alg,
		nonce,
		kid: account_uri,
	};
	const finalize_protected_b64 = b64(JSON.stringify(finalize_protected_json));

	const unarmor = /-----BEGIN CERTIFICATE REQUEST-----([A-Za-z0-9+\/=\s]+)-----END CERTIFICATE REQUEST-----/;
	const matches = unarmor.exec(pem);
	if (!matches || matches.length < 1) {
		throw "wrong cert format";
	}
	const csr_der = matches[1].replace(/\r?\n/g, '');
	const finalize_payload_json = {
		csr: Buffer.from(csr_der, "base64").toString("base64url"),
	};
	const finalize_payload_b64 = b64(JSON.stringify(finalize_payload_json));

	return {
		finalize_payload_b64,
		finalize_protected_b64,
		cmd: `${finalize_protected_b64}.${finalize_payload_b64}`,
	};
}

// 4f
export async function validateFinalizeAsync({
	account,
	account_uri,
	directory,
	finalize_payload_b64,
	finalize_protected_b64,
	openssl_finalize_order_signature,
	order,
	order_uri,
}: {
	account: Account;
	account_uri: string;
	directory: DirectoryResponse;
	finalize_payload_b64: string;
	finalize_protected_b64: string;
	openssl_finalize_order_signature: string;
	order: OrderResponse;
	order_uri: string;
}) {
	const signature = hex2b64(openssl_finalize_order_signature);
	const response = await fetch(order.finalize, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: finalize_protected_b64,
			payload: finalize_payload_b64,
			signature,
		}),
	});

	if (response.status !== 200) {
		console.log(response.status);
		console.log(await response.json());
		throw "Finalizing failed. Please start back at Step 1.";
	}
	// @ts-ignore TODO check response
	const finalize_response = (await response.json()) as FinalizeResponse;
	const nonce = await getNonceAsync(directory);
	const recheck_order_protected_b64 = b64(JSON.stringify({
		url: order_uri,
		alg: account.alg,
		nonce,
		kid: account_uri,
	}));

	return {
		recheck_order_protected_b64,
		cmd: `${recheck_order_protected_b64}.${RECHECK_ORDER_PAYLOAD_B64}`,
	};
}

// 4g
export async function recheckOrderAsync({
	account,
	account_uri,
	directory,
	openssl_recheck_order_signature,
	order_uri,
	recheck_order_protected_b64,
}: {
	account: Account;
	account_uri: string;
	directory: DirectoryResponse;
	openssl_recheck_order_signature: string;
	order_uri: string;
	recheck_order_protected_b64: string;
}) {
	const signature = hex2b64(openssl_recheck_order_signature);
	const request = await fetch(order_uri, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: recheck_order_protected_b64,
			payload: RECHECK_ORDER_PAYLOAD_B64,
			signature,
		}),
	});

	if (request.status !== 200) {
		throw "TODO";
	}

	// TODO type
	const order = (await request.json()) as ValidOrderResponse;
	if (["pending", "processing", "ready"].includes(order.status)) {
		throw "TODO";
	} else if (order.status === "valid") {
		const nonce = await getNonceAsync(directory);
		const cert_protected_json = {
			url: order.certificate,
			alg: account.alg,
			nonce,
			kid: account_uri,
		};
		const cert_protected_b64 = b64(JSON.stringify(cert_protected_json));
		return {
			cert_uri: order.certificate,
			cert_protected_b64,
			cmd: `${cert_protected_b64}.${CERT_PAYLOAD_B64}`,
		};
	} else {
		throw "TODO";
	}
}

// 4h
export async function getCertificateAsync({
	cert_uri,
	cert_protected_b64,
	openssl_cert_signature,
}: {
	cert_uri: string;
	cert_protected_b64: string;
	openssl_cert_signature: string;
}) {
	const signature = hex2b64(openssl_cert_signature);
	const response = await fetch(cert_uri, {
		method: "POST",
		headers: FETCH_HEADERS,
		body: JSON.stringify({
			protected: cert_protected_b64,
			payload: CERT_PAYLOAD_B64,
			signature,
		}),
	});

	if (response.status !== 200) {
		throw "TODO";
	}

	return await response.text();
}
