export interface DirectoryResponse {
	keyChange: string;
	meta: {
		caaIdentities: string[];
		profiles: {
			classic: string;
			shortlived: string;
			tlsserver: string;
		};
		termsOfService: string;
		website: string;
	};
	newAccount: string;
	newNonce: string;
	newOrder: string;
	renewalInfo: string;
	revokeCert: string;
}

interface Identifier {
	type: string;
	value: string;
}

export interface OrderResponse {
	status: string;
	/** domains */
	identifiers: Identifier[];
	/** uris */
	authorizations: string[];
	/** uri */
	finalize: string;
	/** Time UTC */
	expires: string;
}

export interface ValidOrderResponse extends OrderResponse {
	/** URI */
	certificate: string;
}

export interface AuthResponse {
	challenges: Challenge[];
	identifier: Identifier;
	status: string;
	wildcard: boolean;
}

/** @deprecated */
export interface DNSChallenge {
	status: string;
	token: string;
	type: string;
	url: string;
}

export interface Challenge {
	status: string;
	/** IMPORTANT */
	token: string;
	type: "tls-alpn-01" | "http-01" | "dns-01";
	url: string;
}

export interface FinalizeResponse {
	/** URIs */
	authorizations: string[];
	/** URI */
	finalize: string[];
	identifiers: Identifier[];
	status: string;
}
