# CSRGenerator

This is a tool to generate CSRs for the SM-PKI.

## Generating Keys

Production keys can be generated using [Brainpool Keygen
FIPS](http://192.168.118.4/EBSnet/documentation/brainpool-keygen-fips/). This
generates secure private keys in FIPS mode.

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

The [`ans1js`](https://github.com/lapo-luchini/asn1js) tool can be used to
analyze the ASN.1 structure and compare the examples against what we create.
There is a hosted version unter [lapo.it/asn1js/](https://lapo.it/asn1js/)

## TODO

- [ ] Integrate `Keygen FIPS` into this project. There were conflicts between
      the BouncyCastle dependencies
- [ ] Creation of Renewal CSRs
- [ ] Create PEM encoded CSR so we don't have to convert by hand. This is more
      or less a simple Base64 encoding of the CSR, with fixed line length.
