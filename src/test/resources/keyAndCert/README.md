# Generate Test Cases

```
openssl ecparam -genkey -name brainpoolP256r1 -out a.key
openssl ecparam -genkey -name brainpoolP256r1 -out b.key
openssl req -x509 -key a.key -out a.cer -sha256 -days 365000 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```
