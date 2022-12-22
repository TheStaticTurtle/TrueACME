# TrueACME

TrueACME is a python script to deploy TLS certificate to TrueNAS.

Currently, it uses a standalone server running on port 3000 that the acme server needs to access to validate the challenge. 
You can achieve this by some rules on your reverse proxy of if you run an acme locally, you can modifiy the `/etc/hosts` file temporarily for example.

The end-goal would be to create a custom provider to be able to run this script on truenas itself without proxies or hacks.

TrueACME uses https://github.com/komuw/sewer as an integrated acme client, so if you need to use an other provider than the standalone http-01 challenge you can do so by implementing it (or stealing it from someone who did)

TrueACME is meant to be configured with environment variable but also support the `.env` file:

| Name | Default value | What |
|------|------|---------------|
|CERTIFICATE_DOMAIN|`truenas.domain.local`|Domain name of truenas|
|||
|TRUENAS_API_KEY|`my-api-key`|API Key from truenas|
|TRUENAS_ADDRESS|`http://truenas.domain.local`|Address of truenas|
|TRUENAS_USE_CERT_FOR__UI|`True`|Set the certificate for the UI|
|TRUENAS_USE_CERT_FOR__S3|`False`|Set the certificate for the S3 server|
|TRUENAS_USE_CERT_FOR__FTP|`False`|Set the certificate for the FTP server|
|TRUENAS_USE_CERT_FOR__WEBDAV|`False`|Set the certificate for the WebDAV server|
|TRUENAS_USE_CERT_FOR__APPS|`False`|Set the certificate for apps|
|TRUENAS_CERT_BASE_NAME|`trueacme`|Prefix in the certificate list|
|||
|ACME_DIRECTORY_URL|`https://acme-v02.api.letsencrypt.org/directory`|Url of the acme server|
|||
|CERTIFICATE_PRIVATE_PATH|`certificate.pem`|Path where the certificate secret key is stored|
|CERTIFICATE_PUBLIC_PATH|`certificate.crt`|Path where the certificate public key is stored|
|ACCOUNT_PRIVATE_PATH|`acme_account_key.pem`|Path where the account secret key is stored|
|||
|VERIFY_SSL_CERT|`False`|Verify certificates of request made by TrueACME|

The script also deletes all old certificates with either the CommonName or DNS entries in the SubjectAlternativeName equal to the configured domain

## License
See the [LICENSE.md](LICENSE.md) file