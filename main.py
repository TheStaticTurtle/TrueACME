import json
import subprocess
import sys
import time
from datetime import datetime
import requests
import urllib3
import coloredlogs
import logging
import os.path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import sewer.client
from sewer.crypto import AcmeKey, AcmeAccount
import http01_truenas_provider

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
coloredlogs.install(level=logging.DEBUG, fmt="[%(asctime)s] [%(name)s] [%(levelname)s] %(message)s")
logging.getLogger("urllib3.connectionpool").setLevel(logging.INFO)
logger = logging.getLogger("main.cert")
logger_truenas = logging.getLogger("main.truenas")

try:
    if os.path.exists(".env"):
        from dotenv import load_dotenv
        load_dotenv()
except ImportError as e:
    logger.error("Failed to import dotenv, please install python-dotenv to use a .env file")

CERTIFICATE_DOMAIN = os.environ.get("CERTIFICATE_DOMAIN", "truenas.local")

TRUENAS_USE_CERT_FOR__UI = os.environ.get("TRUENAS_USE_CERT_FOR__UI", "True") == "True"
TRUENAS_USE_CERT_FOR__S3 =  os.environ.get("TRUENAS_USE_CERT_FOR__S3", "False") == "True"
TRUENAS_USE_CERT_FOR__FTP = os.environ.get("TRUENAS_USE_CERT_FOR__FTP", "False") == "True"
TRUENAS_USE_CERT_FOR__WEBDAV = os.environ.get("TRUENAS_USE_CERT_FOR__WEBDAV", "False") == "True"
TRUENAS_USE_CERT_FOR__APPS = os.environ.get("TRUENAS_USE_CERT_FOR__APPS", "False") == "True"
TRUENAS_CERT_BASE_NAME = os.environ.get("TRUENAS_CERT_BASE_NAME", "trueacme")

ACME_DIRECTORY_URL = os.environ.get("ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory")
ACME_CONTACT_EMAIL = os.environ.get("ACME_CONTACT_EMAIL", "root@localhost")
CERTIFICATE_PRIVATE_PATH = os.environ.get("CERTIFICATE_PRIVATE_PATH", "certificate.pem")
CERTIFICATE_PUBLIC_PATH = os.environ.get("CERTIFICATE_PUBLIC_PATH", "certificate.crt")
ACCOUNT_PRIVATE_PATH = os.environ.get("ACCOUNT_PRIVATE_PATH", "acme_account_key.pem")

VERIFY_SSL_CERT = os.environ.get("VERIFY_SSL_CERT", "False") == "True"

def delete_truenas_api_key():
    proc = subprocess.Popen("midclt call api_key.query", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = proc.communicate()

    try:
        apikeys_query_result = json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.error(f"Failed list api keys from truenas \"{stdout}\" \"{stderr}\": {e}")
        sys.exit(-1)

    key_already_present = [x for x in apikeys_query_result if x["name"] == "trueacme_temp"]
    if len(key_already_present) > 0:
        logger_truenas.warning("trueacme_temp api key was already present, deleting")
        subprocess.Popen(f"midclt call api_key.delete {key_already_present[0]['id']}", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        time.sleep(0.5)
    else:
        logger_truenas.info("trueacme_temp not present")
def get_truenas_api_key():
    delete_truenas_api_key()

    logger_truenas.info("Creating trueacme_temp api key")

    proc = subprocess.Popen("midclt call api_key.create '{\"name\":\"trueacme_temp\"}'", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = proc.communicate()

    try:
        apikeys_create_result = json.loads(stdout)
    except json.JSONDecodeError as e:
        logger.error(f"Failed create truenas api key \"{stdout}\" \"{stderr}\": {e}")
        sys.exit(-1)

    logger_truenas.info(f"Got a new API key: {apikeys_create_result['key']}")
    return apikeys_create_result['key']

TRUENAS_ADDRESS = "http://localhost"
TRUENAS_API_KEY = get_truenas_api_key()


account_exists = os.path.exists(ACCOUNT_PRIVATE_PATH)
if account_exists:
    logger.info("account key already exists, loading it")
    account = AcmeAccount.read_pem(ACCOUNT_PRIVATE_PATH)
else:
    logger.info("account key doesn't exists, creating a new one")
    account = AcmeAccount.create("rsa2048")
    account.write_pem(ACCOUNT_PRIVATE_PATH)

certificate_exists = os.path.exists(CERTIFICATE_PRIVATE_PATH)
if account_exists:
    logger.info("certificate key already exists, will renew")
    certificate_key = AcmeKey.read_pem(CERTIFICATE_PRIVATE_PATH)
else:
    logger.info("certificate key doesn't exists, creating a new one")
    certificate_key = AcmeKey.create("rsa2048")
    certificate_key.write_pem(CERTIFICATE_PRIVATE_PATH)

try:
    provider = http01_truenas_provider.Provider()

    client = sewer.client.Client(
        domain_name=CERTIFICATE_DOMAIN,
        account=account,
        domain_alt_names=[],
        provider=provider,
        cert_key=certificate_key,
        is_new_acct=not account_exists,
        contact_email=ACME_CONTACT_EMAIL,
        ACME_DIRECTORY_URL=ACME_DIRECTORY_URL,
        ACME_VERIFY=VERIFY_SSL_CERT
    )

    certificate_armor = client.get_certificate()

except Exception as e:
    logger.error(f"Failed to create a certificate for {CERTIFICATE_DOMAIN}: {e}")
    sys.exit(-1)

with open(CERTIFICATE_PUBLIC_PATH, 'w') as f:
    f.write(certificate_armor)

certificate = x509.load_pem_x509_certificate(certificate_armor.encode("utf8"), default_backend())

certificate_cn = certificate.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
certificate_san = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
certificate_san_dns_names = certificate_san.value.get_values_for_type(x509.DNSName)
certificate_san_ipaddress = certificate_san.value.get_values_for_type(x509.IPAddress)

logger.info(
    f"Successfully created a certificate for: {certificate_cn}, <SubjectAlternativeName dns={certificate_san_dns_names} ip={certificate_san_ipaddress}>")

session = requests.Session()
session.headers.update({
    'Content-Type': 'application/json',
    'Authorization': f'Bearer {TRUENAS_API_KEY}'
})

now = datetime.now()

truenas_cert_name = f"{TRUENAS_CERT_BASE_NAME}-{now.isoformat().replace(':', '-').split('.')[0].replace('T', '_')}"

resp_import = session.post(TRUENAS_ADDRESS + '/api/v2.0/certificate/', verify=VERIFY_SSL_CERT, json={
    "create_type": "CERTIFICATE_CREATE_IMPORTED",
    "name": truenas_cert_name,
    "certificate": certificate_armor,
    "privatekey": certificate_key.to_pem(),
})

if resp_import.status_code == 200:
    logger_truenas.info("Certificate import successful")
else:
    logger_truenas.info(f"Certificate import failed: {resp_import.text}")
    sys.exit(-1)

time.sleep(5)

resp_list = session.get(TRUENAS_ADDRESS + '/api/v2.0/certificate/', verify=VERIFY_SSL_CERT, params={
    'limit': 0
})

if resp_list.status_code == 200:
    logger_truenas.info("Retrieved certificate list successfully")
else:
    logger_truenas.info(f"Failed to retrieve the certificate list: {resp_list.text}")
    sys.exit(-1)

truenas_certificate_list = resp_list.json()

truenas_cert_id = None
for tn_cert_data in truenas_certificate_list:
    if tn_cert_data["name"] == truenas_cert_name:
        truenas_cert_id = tn_cert_data["id"]

if truenas_cert_id is None:
    logger_truenas.info(f"Failed to find the newly created certificate in list")
    sys.exit(-1)

if TRUENAS_USE_CERT_FOR__UI:
    resp_set_cert = session.put(TRUENAS_ADDRESS + '/api/v2.0/system/general/', verify=VERIFY_SSL_CERT, json={
        'ui_certificate': truenas_cert_id
    })
    if resp_set_cert.status_code == 200:
        logger_truenas.info("Successfully set UI certificate")
    else:
        logger_truenas.info(f"Failed to set certificate for UI: {resp_set_cert.text}")
        sys.exit(-1)
if TRUENAS_USE_CERT_FOR__S3:
    resp_set_cert = session.put(TRUENAS_ADDRESS + '/api/v2.0/s3/', verify=VERIFY_SSL_CERT, json={
        'certificate': truenas_cert_id,
        'tls_server_uri': CERTIFICATE_DOMAIN
    })
    if resp_set_cert.status_code == 200:
        logger_truenas.info("Successfully set S3 certificate")
    else:
        logger_truenas.info(f"Failed to set certificate for S3: {resp_set_cert.text}")
        sys.exit(-1)
if TRUENAS_USE_CERT_FOR__FTP:
    resp_set_cert = session.put(TRUENAS_ADDRESS + '/api/v2.0/ftp/', verify=VERIFY_SSL_CERT, json={
        'ssltls_certificate': truenas_cert_id
    })
    if resp_set_cert.status_code == 200:
        logger_truenas.info("Successfully set FTP certificate")
    else:
        logger_truenas.info(f"Failed to set certificate for FTP: {resp_set_cert.text}")
        sys.exit(-1)
if TRUENAS_USE_CERT_FOR__WEBDAV:
    resp_set_cert = session.put(TRUENAS_ADDRESS + '/api/v2.0/webdav/', verify=VERIFY_SSL_CERT, json={
        'certssl': truenas_cert_id
    })
    if resp_set_cert.status_code == 200:
        logger_truenas.info("Successfully set WebDAV certificate")
    else:
        logger_truenas.info(f"Failed to set certificate for WebDAV: {resp_set_cert.text}")
        sys.exit(-1)
if TRUENAS_USE_CERT_FOR__APPS:
    resp_apps = session.get(TRUENAS_ADDRESS + '/api/chart/release', verify=VERIFY_SSL_CERT, json={
        'limit': 0
    })
    if resp_apps.status_code == 200:
        logger_truenas.info("Successfully retrieved app list certificate")
    else:
        logger_truenas.info(f"Failed to retrieved app list: {resp_apps.text}")
        sys.exit(-1)

    for application in resp_apps.json():
        logger_truenas.debug(f"Working on {application['name']}")

        # Filter out every configuration object that starts with "ix". Those are generated.
        config = {k: v for (k, v) in application['config'].items() if not k.startswith("ix")}

        application_id = application['id']

        # Application has ingress setup and enabled with tls
        if config.get("ingress", False) and config['ingress']['main']['enabled'] and len(
                config['ingress']['main']['tls']) > 0:
            logger_truenas.debug(f"Modifying {application['name']} to use the new certificate")

            # Update the TLS certificate ID
            for idx, tls in enumerate(config['ingress']['main']['tls']):
                tls['scaleCert'] = truenas_cert_id
                config['ingress']['main']['tls'][idx] = tls

            resp_set_cert = session.put(TRUENAS_ADDRESS + f'/api/v2.0/chart/release/id/{application_id}', verify=VERIFY_SSL_CERT, json={
                'values': config
            })
            if resp_set_cert.status_code == 200:
                logger_truenas.info(f"Successfully set certificate for {application['name']} !")
            else:
                logger_truenas.error(f"Failed to set certificate for {application['name']}: {resp_set_cert.text}")

truenas_certs_to_delete = []
for tn_cert_data in truenas_certificate_list:
    if tn_cert_data["CA_type_existing"] or tn_cert_data["CA_type_internal"] or tn_cert_data["CA_type_intermediate"]:
        logger.info(f"skipped ca, {tn_cert_data['name']}")
        continue
    if tn_cert_data["cert_type_CSR"]:
        logger.info(f"skipped csr, {tn_cert_data['name']}")
        continue
    if tn_cert_data["internal"] != "NO":
        logger.info(f"skipped internal, {tn_cert_data['name']}")
        continue

    if tn_cert_data["id"] == truenas_cert_id:
        logger.info(f"skipped just imported, {tn_cert_data['name']}")
        continue

    tn_cert = x509.load_pem_x509_certificate(tn_cert_data["certificate"].encode("utf8"), default_backend())

    tn_cert_cns = [x.value for x in tn_cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)]
    tn_cert_san = tn_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    tn_cert_san_dns_names = tn_cert_san.value.get_values_for_type(x509.DNSName)

    for tn_cert_domain in tn_cert_san_dns_names + tn_cert_cns:
        if tn_cert_domain == CERTIFICATE_DOMAIN:
            truenas_certs_to_delete.append(tn_cert_data)
            logger.info(f"marked {tn_cert_data['name']} (/{tn_cert_cns}/{tn_cert_san_dns_names}/) for deletion")
            break

if TRUENAS_USE_CERT_FOR__S3:
    resp_restart = session.post(TRUENAS_ADDRESS + '/api/v2.0/service/restart', verify=VERIFY_SSL_CERT, json={
        'service': 's3'
    })
    if resp_restart.status_code == 200:
        logger_truenas.info("Successfully restarted S3 service")
    else:
        logger_truenas.info(f"Error restarting S3 service: {resp_restart.text}")
if TRUENAS_USE_CERT_FOR__FTP:
    resp_restart = session.post(TRUENAS_ADDRESS + '/api/v2.0/service/restart', verify=VERIFY_SSL_CERT, json={
        'service': 'ftp'
    })
    if resp_restart.status_code == 200:
        logger_truenas.info("Successfully restarted FTP service")
    else:
        logger_truenas.info(f"Error restarting FTP service: {resp_restart.text}")
if TRUENAS_USE_CERT_FOR__WEBDAV:
    resp_restart = session.post(TRUENAS_ADDRESS + '/api/v2.0/service/restart', verify=VERIFY_SSL_CERT, json={
        'service': 'webdav'
    })
    if resp_restart.status_code == 200:
        logger_truenas.info("Successfully restarted WebDAV service")
    else:
        logger_truenas.info(f"Error restarting WebDAV service: {resp_restart.text}")
# Reload UI last
if TRUENAS_USE_CERT_FOR__UI:
    # Reload nginx with new cert
    # If everything goes right in 12.0-U3 and later, it returns 200
    # If everything goes right with an earlier release, the request fails with a ConnectionError
    resp_reload = session.post(TRUENAS_ADDRESS + '/api/v2.0/system/general/ui_restart', verify=VERIFY_SSL_CERT)

    if resp_reload.status_code == 200:
        logger_truenas.info("Successfully reloaded UI")
    elif resp_reload.status_code != 405:
        logger_truenas.info(f"Failed reload UI: {resp_reload.text}")
    else:
        try:
            resp_reload2 = session.get(TRUENAS_ADDRESS + '/api/v2.0/system/general/ui_restart', verify=VERIFY_SSL_CERT)
            logger_truenas.info(f"Failed to reload UI: {resp_reload2.text}")
        except requests.exceptions.ConnectionError:
            logger_truenas.info("Successfully reloaded UI")

time.sleep(2.5)

for tn_cert_data in truenas_certs_to_delete:
    resp_delete = session.delete(TRUENAS_ADDRESS + f"/api/v2.0/certificate/id/{tn_cert_data['id']}",
                                 verify=VERIFY_SSL_CERT)

    if resp_delete.status_code == 200:
        logger_truenas.info(f"Successfully deleted: {tn_cert_data['name']}")
    else:
        logger_truenas.info(f"Failed to deleted: {tn_cert_data['name']}: {resp_delete.text}")