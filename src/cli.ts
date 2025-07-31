#!/usr/bin/env node

import {
	existsSync,
	readFileSync,
	writeFileSync,
} from "node:fs";
import yargs from "yargs";
import { hideBin } from "yargs/helpers";
import forge from "node-forge";
import chalk from "chalk";
import ora from "ora";

import {
	proxy_url,
	gen_dnstoken,
	populateDirectoryAsync,
	createAccountAsync,
	createOrder,
	createOrderCmdAsync,
	validateRegistrationAsync,
	validateUpdateAsync,
	validateOrderAsync,
	buildAuthorizationAsync,
	validateAuthorizationAsync,
	confirmChallengeAsync,
	validateChallengeAsync,
	checkAuthorizationAsync,
	finalizeOrderAsync,
	validateFinalizeAsync,
	recheckOrderAsync,
	getCertificateAsync,
} from "./lib";
import {
	prompt,
	prompt_without_output,
	check_pause,
	accept_term,
} from "./prompt";

import {
	type Challenge,
} from "./types"

import {
	opensslSignAsync,
} from "./openssl_exec";

const argv = yargs(hideBin(process.argv))
	.usage("Usage: $0 [options]")
	.example([
		[
			"$0 -k account.key -p account.pub -s domain.csr -e test@example.com -c domain.crt",
			"Get a certificate and save to `domain.crt`"
		],
		[
			"https_proxy=http://localhost:8080 certcli ...",
			"Using a HTTP proxy if the connectivity to Let's Encrypt API is not stable"
		],
	])
	.option("priv_key", {
		alias: "k",
		describe: "Path to your account private key",
		type: "string",
		demandOption: true,
	})
	.option("pub_key", {
		alias: "p",
		describe: "Path to your account public key",
		type: "string",
		demandOption: true,
	})
	.option("csr", {
		alias: "s",
		describe: "Path to the certificate signing request",
		type: "string",
		demandOption: true,
	})
	.option("email", {
		alias: "e",
		describe: "Contact email",
		type: "string",
		demandOption: true,
	})
	.option("cert_file", {
		alias: "c",
		describe: "Path to save the certificate file",
		type: "string",
		demandOption: false,
	})
	.option("dry_run", {
		alias: "d",
		describe: "Perform a dry run",
		type: "count",
		demandOption: false,
	})
	.help()
	.alias("h", "help")
	.parseSync();

if (!existsSync(argv.priv_key)) {
	console.error(`Private key ${argv.priv_key} doesn't exist or cannot be read`);
	process.exit(1);
}

if (!existsSync(argv.pub_key)) {
	console.error(`Public key ${argv.pub_key} doesn't exist or cannot be read`);
	process.exit(1);
}

if (!existsSync(argv.csr)) {
	console.error(`Certificate signing request ${argv.csr} doesn't exist or cannot be read`);
	process.exit(1);
}

const pubkey = readFileSync(argv.pub_key, "utf-8");
const pem    = readFileSync(argv.csr,      "utf8");

async function main() {
	let domains = [];
	// parse and show info
	do {
		// Get domain names
		const csr = forge.pki.certificationRequestFromPem(pem);
		const extReqAttr = csr.getAttribute({ name: "extensionRequest" });
		if (!extReqAttr) {
			console.error("⚠️  No extensions found in CSR.");
			process.exit(0);
		}
		const extensions = extReqAttr.extensions;
		if (!extensions) {
			console.error("⚠️  No extensions found in CSR.");
			process.exit(0);
		}
		const sanExt = extensions.find(ext => ext.id === forge.pki.oids.subjectAltName);
		if (!sanExt || !sanExt.altNames) {
			console.log("⚠️  No SAN (Subject Alternative Name) present.");
			process.exit(0);
		}
		domains = sanExt.altNames
			.filter(gn => gn.type === 2)      // NOTE type 2 = DNSName
			.map(gn => gn.value) as string[];

		if (domains.length === 0) {
			console.error("Couldn't find any domains in the CSR.");
			process.exit(1);
		}

		console.log(chalk.bold("\n📄 Summary of Certificate Request"));
		console.log(chalk.gray("----------------------------------"));
		console.log(chalk.cyan("Account Key:"));
		console.log(`  - ${chalk.green(argv.priv_key)}`);
		console.log(chalk.cyan("Public Key:"));
		console.log(`  - ${chalk.green(argv.pub_key)}`);
		console.log(chalk.cyan("Email:"));
		console.log(`  - ${chalk.yellow(argv.email)}`);
		console.log(chalk.cyan("Domains:"));
		domains.forEach((domain) => {
			console.log(`  - ${chalk.magenta(domain)}`);
		});

		console.log(chalk.cyan("Certificate Output:"));
		if (argv.cert_file) {
			console.log(`  - ${chalk.green(argv.cert_file)}`);
		} else {
			console.log(`  - ${chalk.red("Will be printed to terminal")}`);
		}

		if (proxy_url) {
			console.log(chalk.cyan("Using Proxy:"));
			console.log(`  - ${chalk.yellow(proxy_url)}`);
		}

		if (argv.dry_run) {
			console.log("🧪 Dry run mode enabled. Exiting without performing any actions.");
			process.exit(0);
		}
	} while (0);

	await check_pause();

	const stage_dir = ora(`Fetching directories from Let's Encrypt...`).start();
	const directory = await populateDirectoryAsync();
	stage_dir.succeed(`Directories fetched`);

	const stage_account = ora(`Validating account info...`).start();
	const account = await createAccountAsync({
		email: argv.email,
		pubkey,
	});
	stage_account.succeed(`Account validated`);

	const stage_order = ora(`Creating order...`).start()
	const order = createOrder({
		domains,
	});
	const {
		registration_protected_b64,
		cmd: order_cmd,
	} = await createOrderCmdAsync({
		directory,
		account,
	});
	stage_order.text = `Order created, signing...`;
	const openssl_order_signature = await opensslSignAsync({
		content: order_cmd,
		priv_key: argv.priv_key,
	});
	stage_order.succeed("Order created");

	await accept_term();

	const stage_term = ora("Accepting terms...").start();
	const {
		account_uri,
		update_protected_b64,
		cmd: registration_cmd,
	} = await validateRegistrationAsync({
		directory,
		account,
		openssl_order_signature,
		registration_protected_b64,
	});
	const openssl_registration_signature = await opensslSignAsync({
		content: registration_cmd,
		priv_key: argv.priv_key,
	});
	stage_term.succeed("Terms accepted");

	const stage_validate = ora(`Updating yout account email ${argv.email}...`).start();
	const {
		order_protected_b64,
		cmd: order_sig_cmd,
	} = await validateUpdateAsync({
		account,
		account_uri,
		directory,
		openssl_registration_signature,
		order,
		update_protected_b64,
	});
	const openssl_validate_order_signature = await opensslSignAsync({
		content: order_sig_cmd,
		priv_key: argv.priv_key,
	});
	stage_validate.succeed("Email updated");

	const stage_update_order = ora("Creating your certificate order").start();
	const {
		order_uri,
		order_response,
	} = await validateOrderAsync({
		directory,
		openssl_validate_order_signature,
		order,
		order_protected_b64,
	});
	stage_update_order.succeed("Order created");

	for (let i = 0; i < order_response.identifiers.length; i++) {
		const stage_load_challenge = ora("Loading challenge...").start();
		const {
			auth_url,
			auth_protected_b64,
			cmd,
		} = await buildAuthorizationAsync({
			idx: i,
			directory,
			order_response,
			account,
			account_uri,
			auth_payload_b64: "",
		});
		const openssl_auth_sig = await opensslSignAsync({
			content: cmd,
			priv_key: argv.priv_key,
		});
		const auth_obj = await validateAuthorizationAsync({
			auth_url,
			auth_protected_b64,
			openssl_auth_sig,
		});
		let domain = auth_obj.identifier.value;
		if (auth_obj.wildcard) {
			domain = "*." + domain;
		}
		stage_load_challenge.succeed(`[${domain}] Challenge loaded`);

		const http_01_challenge = auth_obj.challenges.find(x => x.type === "http-01"),
			dns_01_challenge = auth_obj.challenges.find(x => x.type === "dns-01");

		if (!http_01_challenge && !dns_01_challenge) {
			console.error(`no challenge available for domain ${auth_obj.identifier.value}`);
			continue;
		}

		let chosen_challenge: Challenge | undefined;
		if (http_01_challenge && dns_01_challenge) {
			const ans = (await prompt({
				question: `Choose the challenge type you prefer, [${chalk.cyan("H")}]ttp or [${chalk.cyan("D")}]ns: (H/D) `,
			}));
			if (ans.length === 0) {
				console.log("invalid input, exit...");
				process.exit(1);
			}

			const letter = ans[0].toUpperCase();
			if (letter !== "H" && letter !== "D") {
				console.log("invalid input, exit...");
				process.exit(1);
			}
			chosen_challenge = letter === "H"
				? http_01_challenge
				: dns_01_challenge;
		}
		if (!chosen_challenge) {
			chosen_challenge = http_01_challenge || dns_01_challenge;
		}
		if (!chosen_challenge) {
			throw "no challenge available";
		}

		const token = `${chosen_challenge.token}.${account.thumbprint}`;
		switch (chosen_challenge.type) {
		case "http-01":
			console.log([
				chalk.cyan("Under this url:"),
				chalk.italic.underline(`http://${auth_obj.identifier.value}/.well-known/acme-challenge/${chosen_challenge.token}`),
				chalk.cyan("Serve this content:"),
				chalk.italic(token),
			].join("\n"));
			break;
		case "dns-01":
			const acme_domain = `_acme-challenge.${auth_obj.identifier.value}`;
			console.log([
				chalk.cyan(`For this DNS record`),
				chalk.italic.underline(`${acme_domain}:`),
				chalk.cyan("Set this TXT record:"),
				chalk.italic(await gen_dnstoken(token)),
				chalk.yellow("NOTES:"),
				`  1. To verify the TXT record is being served (this can take a while), you can run:`,
				chalk.cyan(`    dig +short ${acme_domain} TXT`),
				`  2. To use a different DNS server (e.g. ${chalk.cyan("8.8.8.8")}:`,
				chalk.cyan(`    dig +short @8.8.8.8 ${acme_domain} TXT`),
				`  3. ${chalk.red("Wait")} till you can see that new TXT record has propagated`,
			].join("\n"));
			break;
		case "tls-alpn-01":
			console.error("unsupported");
			break;
		}

		const stage_wait_challenge = ora(`[${domain}] When you've update the settings, press ${chalk.cyan("enter")}.`).start();
		await prompt_without_output();
		stage_wait_challenge.succeed(chosen_challenge.type === "http-01"
			? `[${domain}] I'm now serving this file on ${chalk.italic.underline(domain)}`
			: `[${domain}] I can see the TXT record for ${chalk.italic.underline(domain)}`
		);

		const stage_sign_challenge = ora(`[${domain}] Signing challenge...`);
		const {
			challenge_protected_b64,
			cmd: confirm_challenge_cmd,
		} = await confirmChallengeAsync({
			account,
			account_uri,
			challenge: chosen_challenge,
			directory,
		});
		const openssl_challenge_signature = await opensslSignAsync({
			content: confirm_challenge_cmd,
			priv_key: argv.priv_key,
		});
		stage_sign_challenge.succeed(`[${domain}] Challenge signed`);

		const stage_validate_challenge = ora(`[${domain}] Submitting challenge...`);
		const {
			cmd: validate_challenge_cmd,
			recheck_auth_protected_b64,
		} = await validateChallengeAsync({
			account,
			account_uri,
			challenge: chosen_challenge,
			challenge_protected_b64,
			directory,
			openssl_challenge_signature,
		});
		const openssl_validate_challenge_signature = await opensslSignAsync({
			content: validate_challenge_cmd,
			priv_key: argv.priv_key,
		});
		stage_validate_challenge.succeed(`[${domain}] Challenge submitted`);

		const stage_check_challenge = ora(`[${domain}] Checking challenge...`).start();
		const obj = await checkAuthorizationAsync({
			account,
			account_uri,
			challenge: chosen_challenge,
			directory,
			openssl_validate_challenge_signature,
			recheck_auth_protected_b64,
		});
		stage_check_challenge.succeed(`[${domain}] Challenge complete`);

		if (obj.status === "valid")
			continue;

		// FIXME
		console.log(obj);
	}

	const stage_finalize_order = ora(`Finalizing order...`).start();
	const {
		finalize_payload_b64,
		finalize_protected_b64,
		cmd: finalize_order_cmd,
	} = await finalizeOrderAsync({
		account,
		account_uri,
		directory,
		order: order_response,
		pem,
	});
	const openssl_finalize_order_signature = await opensslSignAsync({
		content: finalize_order_cmd,
		priv_key: argv.priv_key,
	});
	const {
		recheck_order_protected_b64,
		cmd: foo,
	} = await validateFinalizeAsync({
		account,
		account_uri,
		directory,
		finalize_payload_b64,
		finalize_protected_b64,
		openssl_finalize_order_signature,
		order: order_response,
		order_uri,
	});
	stage_finalize_order.succeed(`Order finalized`);

	const stage_recheck_order = ora(`Checking certificate generation status...`);
	const openssl_recheck_order_signature = await opensslSignAsync({
		content: foo,
		priv_key: argv.priv_key,
	});
	const {
		cert_uri,
		cert_protected_b64,
		cmd: cert_cmd,
	} = await recheckOrderAsync({
		account,
		account_uri,
		directory,
		openssl_recheck_order_signature,
		order_uri,
		recheck_order_protected_b64,
	});
	stage_recheck_order.succeed(`Certificate ready`);

	const stage_retrieve_certificate = ora(`Retrieving certificate...`).start();
	const openssl_cert_signature = await opensslSignAsync({
		content: cert_cmd,
		priv_key: argv.priv_key,
	});
	const certificate = await getCertificateAsync({
		cert_uri,
		cert_protected_b64,
		openssl_cert_signature,
	});
	stage_retrieve_certificate.succeed(`Certificate retrieved`);

	if (argv.cert_file) {
		writeFileSync(argv.cert_file, certificate, { encoding: "utf8" });
	} else {
		console.log(certificate);
	}
}

main().catch(err => console.error(err));
