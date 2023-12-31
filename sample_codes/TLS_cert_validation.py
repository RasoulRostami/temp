import datetime

import certifi
from OpenSSL import SSL, crypto

data = {
    "public_key": """
-----BEGIN CERTIFICATE-----
MIIEXjCCA0agAwIBAgISBHGV3BzfdZIKZ4vj5cUwy97iMA0GCSqGSIb3DQEBCwUA
MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD
EwJSMzAeFw0yMzA1MTUxMzE3MThaFw0yMzA4MTMxMzE3MTdaMBwxGjAYBgNVBAMT
EXJhc291bC1yb3N0YW1pLmlyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEwbWa
X0epkb09ygW13wiKWDNinorqWRi+dicLUZe4BREU39O5UcsiV9t8lLPhCOgTmatb
9Ze8qYVezX+ua9/U1aOCAk0wggJJMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAU
BggrBgEFBQcDAQYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUwM61
0pVqXovGid8e25xieH/Z+FswHwYDVR0jBBgwFoAUFC6zF7dYVsuuUAlA5h+vnYsU
wsYwVQYIKwYBBQUHAQEESTBHMCEGCCsGAQUFBzABhhVodHRwOi8vcjMuby5sZW5j
ci5vcmcwIgYIKwYBBQUHMAKGFmh0dHA6Ly9yMy5pLmxlbmNyLm9yZy8wHAYDVR0R
BBUwE4IRcmFzb3VsLXJvc3RhbWkuaXIwTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYL
KwYBBAGC3xMBAQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlw
dC5vcmcwggEFBgorBgEEAdZ5AgQCBIH2BIHzAPEAdgB6MoxU2LcttiDqOOBSHumE
FnAyE4VNO9IrwTpXo1LrUgAAAYgfxdQHAAAEAwBHMEUCIBilf/sovm+tGM6qg2/i
OFfDuoJ96zxOEm9GXYsyC/a0AiEAzWLVSZz1BnIRh1UytqZUuVAU3WozKpX7at1O
iVyUecEAdwCt9776fP8QyIudPZwePhhqtGcpXc+xDCTKhYY069yCigAAAYgfxdSl
AAAEAwBIMEYCIQD6Y1wNVcEanJFBB2Vx+rGer9wfE7IRE9jS+XHVCHyMdwIhAKSJ
ShlvQnqNJE76XT5puk5FWfjWm3EX5wSku6/uIoxuMA0GCSqGSIb3DQEBCwUAA4IB
AQAR53G0dX6TjJM5KnWkZpKWUTKMwG5cEcDpR/6Xt0e1PVnAzpx82yOQlqhz8eSO
Q3AJX84flhUwaoEM1r1TT87EiKE+XZZvsUqd7VLuMBTuqYKV7S8P3RjmrqtForSP
xMkDSXS0qh7a6FRueHSAB9aqyci0oIawUqjbXsp+koKDt2G/w0Z5PbFqx9mqhsHZ
j3DUVIGPrXiFVrl8wVvurbfS1d6EjycQWe8uX1gLkExlYsBE4mCUs8//pJ5M8Bqi
LWt0N77el1nJrupFQeNuKahn8WCy3aUskHYeo4t+vAbH2sHR66CxcKpImEqBL789
TTPbC5TdUb5tkXeNayZOPNlq
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw
WhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg
RW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP
R5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx
sxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm
NHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg
Z3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG
/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC
AYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB
Af8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA
FHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw
AoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw
Oi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB
gt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W
PTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl
ikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz
CkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm
lJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4
avAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2
yJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O
yK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids
hCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+
HlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv
MldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX
nLRbwHOoq7hHwg==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYDCCBEigAwIBAgIQQAF3ITfU6UK47naqPGQKtzANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTIxMDEyMDE5MTQwM1oXDTI0MDkzMDE4MTQwM1ow
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQCt6CRz9BQ385ueK1coHIe+3LffOJCMbjzmV6B493XC
ov71am72AE8o295ohmxEk7axY/0UEmu/H9LqMZshftEzPLpI9d1537O4/xLxIZpL
wYqGcWlKZmZsj348cL+tKSIG8+TA5oCu4kuPt5l+lAOf00eXfJlII1PoOK5PCm+D
LtFJV4yAdLbaL9A4jXsDcCEbdfIwPPqPrt3aY6vrFk/CjhFLfs8L6P+1dy70sntK
4EwSJQxwjQMpoOFTJOwT2e4ZvxCzSow/iaNhUd6shweU9GNx7C7ib1uYgeGJXDR5
bHbvO5BieebbpJovJsXQEOEO3tkQjhb7t/eo98flAgeYjzYIlefiN5YNNnWe+w5y
sR2bvAP5SQXYgd0FtCrWQemsAXaVCg/Y39W9Eh81LygXbNKYwagJZHduRze6zqxZ
Xmidf3LWicUGQSk+WT7dJvUkyRGnWqNMQB9GoZm1pzpRboY7nn1ypxIFeFntPlF4
FQsDj43QLwWyPntKHEtzBRL8xurgUBN8Q5N0s8p0544fAQjQMNRbcTa0B7rBMDBc
SLeCO5imfWCKoqMpgsy6vYMEG6KDA0Gh1gXxG8K28Kh8hjtGqEgqiNx2mna/H2ql
PRmP6zjzZN7IKw0KKP/32+IVQtQi0Cdd4Xn+GOdwiK1O5tmLOsbdJ1Fu/7xk9TND
TwIDAQABo4IBRjCCAUIwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYw
SwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5pZGVudHJ1
c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTEp7Gkeyxx
+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEEAYLfEwEB
ATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2VuY3J5cHQu
b3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0LmNvbS9E
U1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFHm0WeZ7tuXkAXOACIjIGlj26Ztu
MA0GCSqGSIb3DQEBCwUAA4IBAQAKcwBslm7/DlLQrt2M51oGrS+o44+/yQoDFVDC
5WxCu2+b9LRPwkSICHXM6webFGJueN7sJ7o5XPWioW5WlHAQU7G75K/QosMrAdSW
9MUgNTP52GE24HGNtLi1qoJFlcDyqSMo59ahy2cI2qBDLKobkx/J3vWraV0T9VuG
WCLKTVXkcGdtwlfFRjlBz4pYg1htmf5X6DYO8A4jqv2Il9DjXA6USbW1FzXSLr9O
he8Y4IWS6wY7bCkjCWDcRQJMEhg76fsO3txE+FiYruq9RUWhiF1myv4Q6W+CyBFC
Dfvp7OOGAN6dEOM4+qR9sdjoSYKEBpsr6GtPAQw4dy753ec5
-----END CERTIFICATE-----
""",
    "private_key": """
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIEqQKu2mCnnJ7zYtZQa2I1zqH5hRfCf4fFjscQM9SA9uoAoGCCqGSM49
AwEHoUQDQgAEwbWaX0epkb09ygW13wiKWDNinorqWRi+dicLUZe4BREU39O5Ucsi
V9t8lLPhCOgTmatb9Ze8qYVezX+ua9/U1Q==
-----END EC PRIVATE KEY-----
""",
}

self_signed_data = {
    "public_key": """
-----BEGIN CERTIFICATE-----
MIICrjCCAZYCEQCnQV8bXxmFve6qG3i6P6U8MA0GCSqGSIb3DQEBCwUAMBUxEzAR
BgNVBAMMCnJhc291bC5lZHUwHhcNMjMwNzIyMDkxODI5WhcNMjQwNzIxMDkxODI5
WjAVMRMwEQYDVQQDDApyYXNvdWwuZWR1MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEApOJFa/e1amAfdLSCoNwX+gEdNcblqLlhCP4Zc18+dt7jSB96K8U9
YpFZutsx1mcFefrjb/R+RAJw/gbpwg/PVvzN2hv2i+sukjxRMWZHWv4h5fnRO7Gm
spghhJ7dsDvh4VTvGnZk/ZhF96LkY2yFz6phLoUiN4QDQbIUH2Ya1N8CAiq+9CJ8
Gs9jcZoQWj/kw2LRAE2+te/FEHGoh8W4xufCYtKnbaqS8/EVHGmeL/+cdkn3ZJMm
S/d37EhJk1+U1sL/1vHtaSgRBplHx2633kIhtT6Z/29z6dqAGprXaJ6PMdy/CTAf
Cislf0zMPtRaMW+1znrZVSXx94zTqHPIkwIDAQABMA0GCSqGSIb3DQEBCwUAA4IB
AQCeeqx9JM6jDQY07EW5B1kzj2KorxGppp37w1cyYNCMMrkMj7sVfonEztlQ8dl+
w10QCAf7ymh3rxfgxt8NpZ2dJffaO6C8tbR2Z50sKeRuF6pWTT+/+Ew9p8r7frE4
+Hj/itL3IZNKeLbYentME27asWEE9TY4uiMXL4mFV7p6Pd9mSbJ16EoZ8z1/675l
6/HxxN6iBd0l+cVjy3m8IrUlvWWEVTbEItDUYkSvIKqnBNfin/AHEjnwpsY9AlUl
abX1rdsHCie1IV1nwG6qabVItzzxDpIyrV6a/GV/7pa7DOngJgtE72dSK6QBR5oW
hQVqqUMUi9PPo5cKBvz7FO5M
-----END CERTIFICATE-----
""",
    "private_key": """
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCk4kVr97VqYB90
tIKg3Bf6AR01xuWouWEI/hlzXz523uNIH3orxT1ikVm62zHWZwV5+uNv9H5EAnD+
BunCD89W/M3aG/aL6y6SPFExZkda/iHl+dE7saaymCGEnt2wO+HhVO8admT9mEX3
ouRjbIXPqmEuhSI3hANBshQfZhrU3wICKr70Inwaz2NxmhBaP+TDYtEATb6178UQ
caiHxbjG58Ji0qdtqpLz8RUcaZ4v/5x2SfdkkyZL93fsSEmTX5TWwv/W8e1pKBEG
mUfHbrfeQiG1Ppn/b3Pp2oAamtdono8x3L8JMB8KKyV/TMw+1Foxb7XOetlVJfH3
jNOoc8iTAgMBAAECggEAAhYeHCGYdtsNpYL/5qS8BrFmZqHhU93cC5UpPtRTJNsb
ru//ZMdliiLeE6MuVQkg55EKkmreXje69rEGGMoEhDsijXXyPoVnMTPTy50na6ly
ov/B6YDesWOS2V5aiRaN/GuqynYg+be7sZYH84nw9vtmU1IF+91HN8GU8i3rSqpq
Wanks/jXZdj53dbYaSh39KI5LWPvDdUf+Pg1ttcOEnrn2Kzsq6oO3z4m0txZ+m/t
8vjQ7uSPqglrKUbGWhikpGSoHX/abIZm8R8rICwJLIK+nXawJfqKAi/emhXZlv+q
0iB64+6xLwIakbfMcgVKmY0xAzfKYXhKGbwEpD3L0QKBgQDeAPpazT0tN8r+bsNN
bTXOWsT1SWc75WyTOEPugiltPwTolT0egKeLTQt1Qb6nLlHiSTZX91zYtCHBrY+M
mdWfha8vO1hoX2BtBHhFp2GtSOzd7MEBdFbfdosgLb4FlTWc/SLxdFYK3qPWWBMz
3L0U1WSOOev7whO6LKBd2zokYwKBgQC+IhHaPh0qqMXau9VoSM/DuIATY90W5ya5
jcXSJoaDGYm0WcQ/UN7n1oNwEUpz5MJ0Wgz8qfZFyz/pyfWzAooZjd+kaAdYs+TL
ehlfnKUpD1mtvinHF2ELNy8oUTpVfrzhBRHoZSWBeMAHmq1NV0wrvnOvd+jto9VV
97RX5j6KEQKBgG6jRCF+iU+Ar6yvXKu4kokdmWy4wTcLdlnEP66ctbKZJoQW5BfQ
fC8jHWO5eR9uKSbB39BlGaNx2iTgr1qdy+WtRQof5EZXygFqqdnkufwXDNzowaNM
7IJ/XIST51B29Pog+YoltT/DhxkqWZ+OEblRQ8TRvvZ/2T7+QIml2MsLAoGBAIi4
SwoaXDLOxedx5hVlNjFRPJe02cicUxZewf9JwLQI6yKK4jl9V6xybnVpmZYYy1OL
ZYdSWEr7ymu81Dby/oc9o7G/NHkucrl2hURhicoqxZvQAI6vWxMLjZd6QW41AnD0
iloIUZ32TG+rZC8XNSjHfLyShyZLBx8YTdBfOl1hAoGAFGSWl0/CzPeKziWY57NJ
OXlN/JFWrIhzrwMbExM4RiQ5xpwwMfmJhd5udXcekavzgPqJA/c9Wot0ziPzht7O
pGPIL/xdcXuuStQ9W4fUP5zrljAs8u4c8wl6mX/TykTf+vBF9+OXTyHiNGKdHo5A
sOMyjhS6KtzUEDaOAq6u9kk=
-----END PRIVATE KEY-----
""",
}


def separate_certificates(certification_pem: str):
    certs = []
    for c in certification_pem.split("\n\n"):
        certs.append(c.strip())
    root = certs[-1]
    untrusted = certs[0]
    intermediate = "\n\n".join(certs[1:])
    return root, untrusted, intermediate


def separate_certificates_2(certification_pem: str):
    certificates = []
    cert_data = ""
    for line in certification_pem.strip().splitlines():
        cert_data += line + "\n"
        if line.strip() == "-----END CERTIFICATE-----":
            certificates.append(cert_data)
            cert_data = ""
    root = certificates[-1]
    untrusted = certificates[0]
    intermediate = "\n\n".join(certificates[1:])
    return root, untrusted, intermediate


def separate_root_certificates():
    root_address = "/etc/ssl/certs/ca-certificates.crt"
    certificates = []
    cert_data = ""
    with open(root_address) as my_file:
        for line in my_file.read().strip().splitlines():
            cert_data += line + "\n"
            if line.strip() == "-----END CERTIFICATE-----":
                certificates.append(cert_data)
                cert_data = ""
    return certificates


# check pem format
certificate = crypto.load_certificate(crypto.FILETYPE_PEM, data.get("public_key"))
private_key = crypto.load_privatekey(crypto.FILETYPE_PEM, data.get("private_key"))
public_key = certificate.get_pubkey()
# check encryption
test_data = b"test_message"
digest = "sha256"
signature = crypto.sign(private_key, test_data, digest)
crypto.verify(certificate, signature, test_data, digest)
# check expire time
if certificate.has_expired():
    raise ValueError("expire")
# check self-signed cert
subject = certificate.get_subject()
issuer = certificate.get_issuer()
if issuer == subject:
    raise ValueError("self signed")

### Full chain check
# test  one
"""
store = crypto.X509Store()
for cert in separate_root_certificates():
    store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
store_ctx = crypto.X509StoreContext(store, certificate)
store_ctx.verify_certificate()
"""


# test two
"""
store = crypto.X509Store()
counter = 1
for cert in separate_certificates(data.get("public_key")):
    print(counter)
    store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, cert))
    counter += 1
store_ctx = crypto.X509StoreContext(store, certificate)
store_ctx.verify_certificate()
"""

# test three
"""
store = crypto.X509Store()
root_address = "/etc/ssl/certs/ca-certificates.crt"
with open(root_address) as my_file:
    store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, my_file.read()))
store_ctx = crypto.X509StoreContext(store, certificate)
store_ctx.verify_certificate()
"""


# test four
"""
import pem

root_address = "/etc/ssl/certs/ca-certificates.crt"
store = crypto.X509Store()
with open(root_address) as my_file:
    certificates = my_file.read().rstrip()
for cert in pem.parse(certificates):
    store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, str(cert)))
store_ctx = crypto.X509StoreContext(store, certificate)
store_ctx.verify_certificate()
"""

# test five
"""
def verify_certificate_context(cert_pem):
    # Load the certificate using pyopenssl
    certificate_obj = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)

    # Create an SSL context using the system's trusted CA certificates (certifi)
    ssl_context = SSL.Context(SSL.TLSv1_2_METHOD)
    ssl_context.load_verify_locations(cafile=certifi.where())

    # Create a store and add the certificate
    store = ssl_context.get_cert_store()
    store.add_cert(certificate_obj)

    # Verify the certificate chain
    try:
        ssl_context.verify_certificate()
        print("Certificate context is valid.")
        return True
    except SSL.Error as e:
        print("Certificate context verification failed:", e)
        return False


verify_certificate_context(data.get("public_key"))
"""

# test six
"""
def verify_certificate_context(cert_pem):
    # Create an SSL context using the system's trusted CA certificates (certifi)
    ssl_context = ssl.create_default_context(cafile=certifi.where())

    # Set the verification mode to CERT_REQUIRED to verify the certificate chain
    ssl_context.verify_mode = ssl.CERT_REQUIRED

    # Load the certificate into the context
    ssl_context.load_verify_locations(cadata=cert_pem)

    # Create a socket and connect to a server using the certificate context
    try:
        with socket.create_connection(("example.com", 443)) as sock:
            with ssl_context.wrap_socket(sock, server_hostname="example.com") as conn:
                pass  # No need to perform any operation, as the handshake will verify the certificate
        print("Certificate context is valid.")
        return True
    except ssl.SSLError as e:
        print("Certificate context verification failed:", e)
        return False
    except socket.error as e:
        print("Socket error:", e)
        return False
"""

# test seven
"""
def verify_certificate_context(cert_pem):
    # Load the certificate using pyopenssl
    certificate_obj = OpenSSL.crypto.load_certificate(
        OpenSSL.crypto.FILETYPE_PEM, cert_pem
    )

    # Create a certificate store and add the certificate
    store = OpenSSL.crypto.X509Store()
    store.add_cert(certificate_obj)

    # Create a certificate context
    context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_2_METHOD)

    # Set the certificate store for the context
    context.set_verify(OpenSSL.SSL.VERIFY_PEER, lambda _, __, ___, ok: ok)
    context.cert_store = store

    # Perform the certificate verification
    try:
        context.verify_certificate()
        print("Certificate context is valid.")
        return True
    except OpenSSL.SSL.Error as e:
        print("Certificate context verification failed:", e)
        return False
"""


# test eight
def verify_certificate_context(cert_pem):
    root, untrusted, intermediate = separate_certificates(data.get("public_key"))
    root = bytes(root, "utf-8")
    untrusted = bytes(untrusted, "utf-8")
    intermediate = bytes(intermediate, "utf-8")
    root_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root)
    intermediate_cert = crypto.load_certificate(crypto.FILETYPE_PEM, intermediate)
    untrusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, untrusted)
    store = crypto.X509Store()
    store.load_locations(certifi.where())
    store.add_cert(root_cert)
    store.add_cert(intermediate_cert)
    store_ctx = crypto.X509StoreContext(store, untrusted_cert)
    store_ctx.verify_certificate()


# test nine not work
"""
def verify_certificate_context(cert_pem):
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, data.get("public_key"))
    store = crypto.X509Store()
    store.load_locations(certifi.where())
    # store.add_cert(certificate)
    store_ctx = crypto.X509StoreContext(store, certificate)
    store_ctx.verify_certificate()
"""

verify_certificate_context(data.get("public_key"))
