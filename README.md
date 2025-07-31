# certcli

This CLI tool is inspired by [gethttpsforfree](https://github.com/diafygi/gethttpsforfree). If you're not familiar with that project, or if you don't know how to generate certificate signing requests (CSRs), probably you should use the [official Let's Encrypt client](https://github.com/certbot/certbot) instead, which can automatically issue and install HTTPS certificates for you.

This CLI is designed for people who know what they are doing and just want to get their HTTPS certificates more easily.

* Sends ACME requests directly to Let's Encrypt (your private keys are **NEVER** sent anywhere).
* Uses `openssl` to perform signing and key operations, make sure it's installed and in your `$PATH`.
* Eliminates the need to manually copy-paste commands and signatures between your browser and terminal.
* Supports both standard and wildcard domain names (e.g. `example.com`, `*.example.com`).
* Prompts you only when necessary, such as:
  * Accepting the Terms of Service
  * Placing challenge files or DNS TXT records

> **Warning** This is **NOT** a certbot-style fully automated tool.
>
> It does **NOT** handle web server reconfiguration, restarts, or renewals.
>
> Instead, it walks you through each step of the ACME flow in the terminal, ideal for users who want a transparent, hands-on process with fewer manual copy-paste steps.

## Installation

Install globally via npm:

```bash
npm install -g certcli
```

Develop locally:

```bash
npm install
npm run build
npm link
```

> If you make changes and rebuild, remember to mark the CLI entry as executable if you're on a \*nix system:

```bash
chmod +x dist/cli.js
```

## Usage

If you've created the files `account.put`, `account.key`, and `domain.csr`, you can run the CLI:

```bash
certcli \
  -p /path/to/account.pub \
  -k /path/to/account.key \
  -s /path/to/domain.csr  \
  -e test@example.com     \
  -c /path/to/domain.crt
```

You can set the environment variable `https_proxy` or `HTTPS_PROXY` to use a proxy server.

CLI options:

```text
$ certcli -h
Usage: certcli [options]

Options:
      --version    Show version number                                 [boolean]
  -k, --priv_key   Path to your account private key          [string] [required]
  -p, --pub_key    Path to your account public key           [string] [required]
  -s, --csr        Path to the certificate signing request   [string] [required]
  -e, --email      Contact email                             [string] [required]
  -c, --cert_file  Path to save the certificate file                    [string]
  -d, --dry_run    Perform a dry run                                     [count]
  -h, --help       Show help                                           [boolean]

Examples:
  certcli -k account.key -p account.pub -s  Get a certificate and save to
  domain.csr -e test@example.com -c         `domain.crt`
  domain.crt
  https_proxy=http://localhost:8080         Using a HTTP proxy if the
  certcli ...                               connectivity to Let's Encrypt API is
                                            not stable
```

If you don't have the required files yet, here's how to create them:

```bash
# Generate an account private key if you don't have one.
# KEEP ACCOUNT.KEY SECRET!
openssl genrsa 4096 > account.key

# Generate the matching public key.
openssl rsa -in account.key -pubout > account.pub

# Generate a TLS private key (used by your web server) if you don't have one.
# KEEP YOUR TLS PRIVATE KEY SECRET, anyone who has it can man-in-the-middle your website.
openssl genrsa 4096 > domain.key

# Generate a CSR (certificate signing request) for the domains you want certs for.
# Replace `foo.com` with your domain. You can include multiple domains.
openssl req -new -sha256 -key domain.key -subj "/" \
  -reqexts SAN -config <(cat /etc/ssl/openssl.cnf \
  <(printf "\n[SAN]\nsubjectAltName=DNS:foo.com,DNS:www.foo.com"))
```

## Privacy

This CLI only communicates with `letsencrypt.org`, it starts by retrieving the ACME directory from the following hardcoded URL:

```
https://acme-v02.api.letsencrypt.org/directory
```

All subsequent request URLs are dynamically discovered through that directory, following the ACME protocol. All HTTP activity is encapsulated in [lib.ts](./src/lib.ts).

Your private key is never sent anywhere, it is only passed to `openssl` locally for signing operations.

## Dependencies:

* [chalk](https://www.npmjs.com/package/chalk) - colorful terminal output
* [node-forge](https://www.npmjs.com/package/node-forge) - CSR parsing to extract domains names
* [ora](https://www.npmjs.com/package/ora) - elegant terminal spinner
* [undici](https://www.npmjs.com/package/undici) - modern HTTP/1.1 client
* [yargs](https://www.npmjs.com/package/yargs) - command-line argument parsing

Unlike [gethttpsforfree](https://github.com/diafygi/gethttpsforfree), this CLI does not use [@lapo/asn1js](https://github.com/lapo-luchini/asn1js).
