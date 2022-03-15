import logging
import socket
import ssl
import sys
from datetime import datetime, timedelta
import OpenSSL

class bcolors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

def get_certificate(host, port=443, timeout=5):
    context = ssl.create_default_context()
    conn = socket.create_connection((host, port))
    sock = context.wrap_socket(conn, server_hostname=host)
    sock.settimeout(timeout)
    try:
        der_cert = sock.getpeercert(True)
    finally:
        sock.close()
    return ssl.DER_cert_to_PEM_cert(der_cert)


def check_cert_on_host(host, days_for_warning=7, debug=False):
    try:
        certificate = get_certificate(host)
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, certificate)
        if debug:
            result = {
                "subject": dict(x509.get_subject().get_components()),
                "issuer": dict(x509.get_issuer().get_components()),
                "serialNumber": x509.get_serial_number(),
                "version": x509.get_version(),
                "notBefore": datetime.strptime(x509.get_notBefore().decode("utf-8") , "%Y%m%d%H%M%SZ"),
                "notAfter": datetime.strptime(x509.get_notAfter().decode("utf-8") , "%Y%m%d%H%M%SZ"),
            }

            extensions = (x509.get_extension(i) for i in range(x509.get_extension_count()))
            extension_data = {e.get_short_name().decode("utf-8"): e for e in extensions}
            result.update(extension_data)
            print(result)
        expires = datetime.strptime(x509.get_notAfter().decode("utf-8") , "%Y%m%d%H%M%SZ")
        expires_in = expires - datetime.now()
        if expires_in < timedelta(days=days_for_warning):
            print(bcolors.WARNING, host, f"EXPIRING IN {expires_in}", bcolors.ENDC)
        else:
            print(bcolors.OKGREEN, host, "OK", bcolors.ENDC)
    except ssl.SSLCertVerificationError as ex:
        print(bcolors.WARNING, host, "NOT OK", ex.verify_message, bcolors.ENDC)
        if debug:
            logging.exception("Failed to verify certificate")
    except Exception as ex:
        logging.exception("Error occurred")

_hosts = ["github.com"]

if __name__ == "__main__":
    
    hosts = sys.argv[1:] if len(sys.argv) > 2 else _hosts
    
    for h in hosts:
        check_cert_on_host(h)
