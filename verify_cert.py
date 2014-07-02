#!/usr/bin/env python
#
# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <dev@robertweidlich.de> wrote this file. As long as you retain this notice
# you can do whatever you want with this stuff. If we meet some day, and you
# think this stuff is worth it, you can buy me a beer in return.
# ----------------------------------------------------------------------------
#


from datetime import datetime, timedelta
from fnmatch import fnmatch
import socket
import ssl
import sys

try:
    import pytz
    import OpenSSL
    from OpenSSL import crypto

    from m2ext import SSL as m2extSSL
    from M2Crypto import X509

    from ndg.httpsclient.subj_alt_name import SubjectAltName

    from pyasn1.codec.der import decoder as der_decoder
    import pyasn1
except ImportError, e:
    print "Error while importing necessary modules: ", e
    print ""
    print "Preparation:"
    print " $ virtualenv venv"
    print " $ . venv/bin/activate"
    print " $ pip install pytz pyasn1 pyOpenSSL ndg-httpsclient m2ext M2Crypto"

# Helper methods for checks


def retrieve_cert_from_server(server, port):
    ctx = OpenSSL.SSL.Context(ssl.PROTOCOL_TLSv1)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)
    s.connect((server, port))
    s.settimeout(None)
    cnx = OpenSSL.SSL.Connection(ctx, s)
    cnx.set_tlsext_host_name(server)
    cnx.set_connect_state()
    cnx.do_handshake()

    x509 = cnx.get_peer_certificate()
    s.close()
    return x509


def get_subj_alt_name(peer_cert):
    '''
    Copied from ndg.httpsclient.ssl_peer_verification.ServerSSLCertVerification
    Extract subjectAltName DNS name settings from certificate extensions

    @param peer_cert: peer certificate in SSL connection.  subjectAltName
    settings if any will be extracted from this
    @type peer_cert: OpenSSL.crypto.X509
    '''
    # Search through extensions
    dns_name = []
    general_names = SubjectAltName()
    for i in range(peer_cert.get_extension_count()):
        ext = peer_cert.get_extension(i)
        ext_name = ext.get_short_name()
        if ext_name == "subjectAltName":
            # PyOpenSSL returns extension data in ASN.1 encoded form
            ext_dat = ext.get_data()
            decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)

            for name in decoded_dat:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        dns_name.append(str(component.getComponent()))
    return dns_name


def validate_certificate(cert, args):
    ctx2 = m2extSSL.Context()
    ctx2.load_verify_locations(cafile=args.cafile, capath=args.capath)
    pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    m2_cert = X509.load_cert_string(pem_cert)
    return ctx2.validate_certificate(m2_cert)

# methods for actual checks
# TODO: add check for revocation and for tlsa records (DANE)


def check_validation(host_name, x509, args):
    org = x509.get_issuer().organizationName
    if validate_certificate(x509, args):
        return (status["OK"], "certified by %s" % org)
    else:
        return (status["CRITICAL"],
                "Certificate by %s failed verification" % org)


def check_servername(host_name, x509, args):
    cn_host_name = x509.get_subject().commonName
    if fnmatch(host_name, cn_host_name):
        return (status["OK"], "hostname in commonName")
    else:
        return (status["CRITICAL"], "not in commonName %s" % cn_host_name)


def check_alt_servername(host_name, x509, args):
    r = check_servername(host_name, x509, args)
    if r[0] == status["OK"]:
        return r
    try:
        subjectAltNames = get_subj_alt_name(x509)
    except pyasn1.error.PyAsn1Error:
        subjectAltNames = []
    host_name_alt_ok = False
    for alt_name in subjectAltNames:
        if fnmatch(server, alt_name):
            host_name_alt_ok = True
            host_name_alt = alt_name

    if len(subjectAltNames) == 0:
        host_name_alt = None
    elif not host_name_alt_ok:
        host_name_alt = subjectAltNames[0]

    if host_name_alt_ok:
        return (status["OK"], "hostname in subjectAltNames")
    else:
        return (
            status["CRITICAL"],
            "hostname not in subjectAltNames: %s and "
            "%s" % (subjectAltNames, r[1])
        )


def check_valid_time_begin(host_name, x509, args):
    now = datetime.now(pytz.utc)
    begin = datetime.strptime(x509.get_notBefore(), "%Y%m%d%H%M%SZ")
    begin = begin.replace(tzinfo=pytz.UTC)
    if begin > now:
        return (
            status["CRITICAL"],
            "Certificate is valid after %s" % x509.get_notBefore()
        )
    return (status["OK"], "Valid Since %s" % x509.get_notBefore())


def check_valid_time_end(server_name, x509, args):
    now = datetime.now(pytz.utc)
    end = datetime.strptime(x509.get_notAfter(), "%Y%m%d%H%M%SZ")
    end = end.replace(tzinfo=pytz.UTC)

    if end < now:
        return (
            status["CRITICAL"],
            "Certificate expired since %s" % x509.get_notAfter()
        )
    if end < now + timedelta(args.warn_days):
        return (
            status["WARNING"],
            "Certificate expires in %i days" % (end-now).days
        )
    return (status["OK"], "Valid until %s" % x509.get_notAfter())


# checks used for --all
available_checks = [
    check_alt_servername,
    check_valid_time_begin,
    check_valid_time_end,
    check_validation
]

# parse command line arguments
import argparse

parser = argparse.ArgumentParser(
    description='Checks validity of SSL server certificates')
parser.add_argument('server', metavar='HOST', type=str, nargs='+',
                    help='hosts to check')
parser.add_argument('--human', action='store_true',
                    help='Colored human readable output')
parser.add_argument('--all', dest='tests',
                    action='store_const', const=available_checks,
                    help="Use all available checks")
parser.add_argument('--expiration', dest='tests',
                    action='append_const', const=check_valid_time_end,
                    help="Check if certificate is before expiration date")
parser.add_argument('--warn-days',
                    action='store', type=int, default=0,
                    help="number of days to warn before certificate expires")
parser.add_argument('--begin', dest='tests',
                    action='append_const', const=check_valid_time_begin,
                    help="Check if certificate is after valid start date")
parser.add_argument('--name', dest='tests',
                    action='append_const', const=check_servername,
                    help="Check if host name used to retrieve certificate is "
                         "in the common name")
parser.add_argument('--name-or-altname', dest='tests',
                    action='append_const', const=check_alt_servername,
                    help="Check if host name used to retrieve certificate is "
                         "in common name or subject alt names")
parser.add_argument('--validate', dest='tests',
                    action='append_const', const=check_validation,
                    help="Validates certificate against hosts built-in "
                         "certificate store")
parser.add_argument('--cafile', action='store', help="Provide an additional"
                                                     " ca-file")
parser.add_argument('--capath', action='store', help="Provide a path with "
                                                     "CAs to validate against")
args = parser.parse_args()

# color human output
color = {
    2: "\033[31;1m",
    1: "\033[33;1m",
    0: "\033[32;1m",
    'end': "\033[0m",
    'error': "\033[33;1m",
}

# nagios status codes
status = {
    "OK": 0,
    "WARNING": 1,
    "CRITICAL": 2
}

# reversed version of above map
reverse_status = dict((v, k) for k, v in status.iteritems())

# global return code and message
result = status["OK"]
msg = []

# loop over all requested servers
for server in args.server:
    s_msg = []
    x509 = None

    # aquire certificate from server
    # TODO: use urlparser to split server into host and port
    try:
        x509 = retrieve_cert_from_server(server, 443)
    except Exception as e:
        result = status["CRITICAL"]
        if args.human:
            msg.append("%30s: %s%s%s\n" %
                       (server, color['error'], e, color['end']))
        else:
            msg.append("Error while retrieving certificate for %s: %s" %
                       (server, e))
        continue

    # do all configured checks
    for test in args.tests:
        test_result, text = test(server, x509, args)
        # update global status in case of failure
        if int(test_result) > result:
            result = int(test_result)
        # add status always for human mode, otherwise only for failures
        if args.human:
            s_msg.append("%s%s%s" % (color[test_result], text, color['end']))
        elif test_result > 0:
            s_msg.append(text)

    # append messages for server to global message, if necessary
    if len(s_msg) > 0:
        s_msg[0] = "%s: %s" % (server, s_msg[0])
    msg.append(", ".join(s_msg))

if args.human:
    print "\n".join(msg)
else:
    print "%s - %s" % (reverse_status[result], ";".join(msg))

sys.exit(result)
