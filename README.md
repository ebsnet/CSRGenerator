# EBSnet CSRGenerator

[![Build](https://github.com/vbrandl/CSRGenerator/actions/workflows/build.yml/badge.svg)](https://github.com/vbrandl/CSRGenerator/actions/workflows/build.yml)

This is a tool to generate CSRs for the [Smart Metering
PKI](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/Smart-metering/Smart-Meterin-PKI/smart-meterin-pki_node.html).

This tool is developed and published by [EBSnet | eEnergy Software
GmbH](https://www.ebsnet.de).

## Generating Keys

Production keys can be generated using [EBSnet
KeyGenFIPS](https://github.com/ebsnet/KeyGenFIPS). This generates secure private
keys in FIPS mode.

Test keys can also be generated using OpenSSL:

```
openssl ecparam -name brainpoolP256r1 -genkey -out tls.pem
```

## Preparing for the CA

At least the DA-RZ Sub CA expects the CSR in PEM encoding. This can be done
using OpenSSL:

```
openssl base64 -in csr.cer -out csr.pem
```

## Examples

In the [`examples`](./examples) subdirectory are examples for the initial and
the renewal CSR.

This tool is developed and published by [EBSnet | eEnergy Software
GmbH](https://www.ebsnet.de).

The [`ans1js`](https://github.com/lapo-luchini/asn1js) tool can be used to
analyze the ASN.1 structure and compare the examples against what we create.
There is a hosted version unter [lapo.it/asn1js/](https://lapo.it/asn1js/)

## Usage

First generate 3 Brainpool keys for signature, encryption and TLS.

```
./bin/CSRGenerator initial --encryption enc.key --signature sig.key --tls tls.key --name example --gln 1234 --out init.pem --uri https://example.com/foo --email foo@example.com
```

## Missing Features (Contributions are Welcome)

- [ ] Creation of Renewal CSRs (here some help would be welcome. Our SubCA
      cannot support us in building valid renewal CSRs and can't debug why their
      management system rejects our CSRs)

## TODO

- [ ] Integrate `Keygen FIPS` into this project. There were conflicts between
      the BouncyCastle dependencies
- [ ] Create PEM encoded CSR so we don't have to convert by hand. This is more
      or less a simple Base64 encoding of the CSR, with fixed line length.

## License

This project is licensed under the GNU AGPLv3 license. The license text can be
found [here](./LICENSE).
