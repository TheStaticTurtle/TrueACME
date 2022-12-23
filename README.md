# TrueACME

TrueACME is a python script to deploy TLS certificate to TrueNAS.

Currently, the script starts a standalone server running on randomly selected free port. 
It then temporarily patch the `/usr/local/etc/nginx/nginx.conf` config to add a new proxypass to the config. For example this part of the config:
```nginx
location / {
    rewrite ^.* $scheme://$http_host/ui/ redirect;
}
```
Will become this after the patch (formatted for readability):
```nginx
location /.well-known/acme-challenge { 
    proxy_pass http://localhost:{server_port}/.well-known/acme-challenge; 
}
location / {
    rewrite ^.* $scheme://$http_host/ui/ redirect;
}
```
`{server_port}` being the randomly selected port.
You can see the `http01_truenas_provider.py` file to see exactly how that works

After an API key from truenas, the script will start the standalone server and will ask the ACME for a challenge.
Once it's received, the server is re-configured to handle this challenge and as nginx redirect the acme challenge directory to us, the ACME server can validate that we own the domain.
After all the challenges have been validated, the server stops, and the script start to update the certificates of truenas according to the configuration.

This tool is meant to be run on the TrueNAS box directly, it takes advantage of the `midclt` to create a temporary API key that it uses to update the certs and reload the UI.
It can be configured with environment variable and also support a `.env` file:

| Name | Default value | What |
|------|------|---------------|
|CERTIFICATE_DOMAIN|`truenas.domain.local`|Domain name of truenas|
|||
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

## Install
TrueACME uses https://github.com/komuw/sewer as an integrated acme client

You will need to install pip, which can be done without the help of `pkg` with the first command. Then you can install the requirements.
```bash
python -m ensurepip
python -m pip install -r requirements.txt
```
If your acme don't have a TOS link, you'll also need to apply this pr to komuw/sewer#226

## License
See the [LICENSE.md](LICENSE.md) file

## Thanks
Here are a few things that helped my this script:
 - https://github.com/komuw/sewer
 - https://github.com/danb35/deploy-freenas
 - https://www.truenas.com/docs/scale/scaletutorials/toptoolbar/managingapikeys