import logging
import socket
from contextlib import closing
import http01_provider
import subprocess
import os

TRUENAS_NGNIX_CONFIG_PATH = os.environ.get("TRUENAS_NGNIX_CONFIG_PATH", "/usr/local/etc/nginx/nginx.conf") 
TRUENAS_NGNIX_WELLKNOWN = "location /.well-known/acme-challenge { proxy_pass http://localhost:{server_port}/.well-known/acme-challenge; }"

TRUENAS_NGNIX_FIND = "location / {"
TRUENAS_NGNIX_REPLACE = f"{TRUENAS_NGNIX_WELLKNOWN} location / {{"

def find_free_port():
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(('localhost', 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return s.getsockname()[1]


class NgnixException(Exception):
    pass

class Provider(http01_provider.Provider):
    def __init__(self, logger=None) -> None:
        if not isinstance(logger, logging.Logger):
            logger = logging.getLogger("sewer.providers.http01.truenas")

        # Init the standalone "http-01" provider
        port = find_free_port()
        super().__init__(logger=logger, host="localhost", port=port)

    def is_ngnix_config_valid(self):
        result = subprocess.run(["nginx", "-t"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if result:
            self.logger.debug("NGINX config is valid")
        else:
            self.logger.error("NGINX config is invalid")
        return result

    def reload_ngnix_config(self):
        result = subprocess.run(["nginx", "-s", "reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
        if result:
            self.logger.info("Reloaded NGINX config")
        else:
            self.logger.error("Failed to reload NGINX config")
        return result

    def _start_server(self):
        if not self.is_ngnix_config_valid():
            raise NgnixException("Config was not valid before starting the server")

        replacement = TRUENAS_NGNIX_REPLACE.replace("{server_port}", str(self._server_address[1]))

        with open(TRUENAS_NGNIX_CONFIG_PATH, "r") as f:
            config_content = f.read()

        if TRUENAS_NGNIX_FIND not in config_content:
            raise NgnixException("Couldn't find the TRUENAS_NGNIX_FIND in the config")

        if replacement in config_content:
            self.logger.warning("Config already present in nginx")

        config_content = config_content.replace(TRUENAS_NGNIX_FIND, replacement)

        with open(TRUENAS_NGNIX_CONFIG_PATH, "w") as f:
            f.write(config_content)

        if not self.is_ngnix_config_valid():
            raise NgnixException("Config was not valid after modification")

        self.reload_ngnix_config()
        return super()._start_server()

    def _stop_server(self):
        if not self.is_ngnix_config_valid():
            raise NgnixException("Config was not valid before starting the server")

        replacement = TRUENAS_NGNIX_REPLACE.replace("{server_port}", str(self._server_address[1]))

        with open(TRUENAS_NGNIX_CONFIG_PATH, "r") as f:
            config_content = f.read()

        if replacement not in config_content:
            self.logger.warning("Config already missing in nginx")
            return super()._stop_server()

        config_content = config_content.replace(replacement, TRUENAS_NGNIX_FIND)

        with open(TRUENAS_NGNIX_CONFIG_PATH, "w") as f:
            f.write(config_content)

        if not self.is_ngnix_config_valid():
            raise NgnixException("Config was not valid after rollback")

        self.reload_ngnix_config()
        return super()._stop_server()
