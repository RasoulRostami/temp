from OpenSSL.crypto import (
    FILETYPE_PEM,
    X509Store,
    X509StoreContext,
    load_certificate,
    load_privatekey,
)
from six import PY3, b, binary_type, u

# root_cert_pem = b(
#     """-----BEGIN CERTIFICATE-----
# MIIC7TCCAlagAwIBAgIIPQzE4MbeufQwDQYJKoZIhvcNAQEFBQAwWDELMAkGA1UE
# BhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdU
# ZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwIhgPMjAwOTAzMjUxMjM2
# NThaGA8yMDE3MDYxMTEyMzY1OFowWDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklM
# MRAwDgYDVQQHEwdDaGljYWdvMRAwDgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9U
# ZXN0aW5nIFJvb3QgQ0EwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAPmaQumL
# urpE527uSEHdL1pqcDRmWzu+98Y6YHzT/J7KWEamyMCNZ6fRW1JCR782UQ8a07fy
# 2xXsKy4WdKaxyG8CcatwmXvpvRQ44dSANMihHELpANTdyVp6DCysED6wkQFurHlF
# 1dshEaJw8b/ypDhmbVIo6Ci1xvCJqivbLFnbAgMBAAGjgbswgbgwHQYDVR0OBBYE
# FINVdy1eIfFJDAkk51QJEo3IfgSuMIGIBgNVHSMEgYAwfoAUg1V3LV4h8UkMCSTn
# VAkSjch+BK6hXKRaMFgxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJJTDEQMA4GA1UE
# BxMHQ2hpY2FnbzEQMA4GA1UEChMHVGVzdGluZzEYMBYGA1UEAxMPVGVzdGluZyBS
# b290IENBggg9DMTgxt659DAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBBQUAA4GB
# AGGCDazMJGoWNBpc03u6+smc95dEead2KlZXBATOdFT1VesY3+nUOqZhEhTGlDMi
# hkgaZnzoIq/Uamidegk4hirsCT/R+6vsKAAxNTcBjUeZjlykCJWy5ojShGftXIKY
# w/njVbKMXrvc83qmTdGl3TAM0fxQIpqgcglFLveEBgzn
# -----END CERTIFICATE-----
# """
# )
# intermediate_cert_pem = b(
#     """-----BEGIN CERTIFICATE-----
# MIICVzCCAcCgAwIBAgIRAMPzhm6//0Y/g2pmnHR2C4cwDQYJKoZIhvcNAQENBQAw
# WDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAklMMRAwDgYDVQQHEwdDaGljYWdvMRAw
# DgYDVQQKEwdUZXN0aW5nMRgwFgYDVQQDEw9UZXN0aW5nIFJvb3QgQ0EwHhcNMTQw
# ODI4MDIwNDA4WhcNMjQwODI1MDIwNDA4WjBmMRUwEwYDVQQDEwxpbnRlcm1lZGlh
# dGUxDDAKBgNVBAoTA29yZzERMA8GA1UECxMIb3JnLXVuaXQxCzAJBgNVBAYTAlVT
# MQswCQYDVQQIEwJDQTESMBAGA1UEBxMJU2FuIERpZWdvMIGfMA0GCSqGSIb3DQEB
# AQUAA4GNADCBiQKBgQDYcEQw5lfbEQRjr5Yy4yxAHGV0b9Al+Lmu7wLHMkZ/ZMmK
# FGIbljbviiD1Nz97Oh2cpB91YwOXOTN2vXHq26S+A5xe8z/QJbBsyghMur88CjdT
# 21H2qwMa+r5dCQwEhuGIiZ3KbzB/n4DTMYI5zy4IYPv0pjxShZn4aZTCCK2IUwID
# AQABoxMwETAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBDQUAA4GBAPIWSkLX
# QRMApOjjyC+tMxumT5e2pMqChHmxobQK4NMdrf2VCx+cRT6EmY8sK3/Xl/X8UBQ+
# 9n5zXb1ZwhW/sTWgUvmOceJ4/XVs9FkdWOOn1J0XBch9ZIiFe/s5ASIgG7fUdcUF
# 9mAWS6FK2ca3xIh5kIupCXOFa0dPvlw/YUFT
# -----END CERTIFICATE-----
# """
# )
# untrusted_cert_pem = b(
#     """-----BEGIN CERTIFICATE-----
# MIICWDCCAcGgAwIBAgIRAPQFY9jfskSihdiNSNdt6GswDQYJKoZIhvcNAQENBQAw
# ZjEVMBMGA1UEAxMMaW50ZXJtZWRpYXRlMQwwCgYDVQQKEwNvcmcxETAPBgNVBAsT
# CG9yZy11bml0MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNh
# biBEaWVnbzAeFw0xNDA4MjgwMjEwNDhaFw0yNDA4MjUwMjEwNDhaMG4xHTAbBgNV
# BAMTFGludGVybWVkaWF0ZS1zZXJ2aWNlMQwwCgYDVQQKEwNvcmcxETAPBgNVBAsT
# CG9yZy11bml0MQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExEjAQBgNVBAcTCVNh
# biBEaWVnbzCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEAqpJZygd+w1faLOr1
# iOAmbBhx5SZWcTCZ/ZjHQTJM7GuPT624QkqsixFghRKdDROwpwnAP7gMRukLqiy4
# +kRuGT5OfyGggL95i2xqA+zehjj08lSTlvGHpePJgCyTavIy5+Ljsj4DKnKyuhxm
# biXTRrH83NDgixVkObTEmh/OVK0CAwEAATANBgkqhkiG9w0BAQ0FAAOBgQBa0Npw
# UkzjaYEo1OUE1sTI6Mm4riTIHMak4/nswKh9hYup//WVOlr/RBSBtZ7Q/BwbjobN
# 3bfAtV7eSAqBsfxYXyof7G1ALANQERkq3+oyLP1iVt08W1WOUlIMPhdCF/QuCwy6
# x9MJLhUCGLJPM+O2rAPWVD9wCmvq10ALsiH3yA==
# -----END CERTIFICATE-----
# """
# )
root_cert_pem = b(
    """-----BEGIN CERTIFICATE-----
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
"""
)
intermediate_cert_pem = b(
    """-----BEGIN CERTIFICATE-----
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
"""
)
untrusted_cert_pem = b(
    """-----BEGIN CERTIFICATE-----
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
"""
)

root_cert = load_certificate(FILETYPE_PEM, root_cert_pem)
intermediate_cert = load_certificate(FILETYPE_PEM, intermediate_cert_pem)
untrusted_cert = load_certificate(FILETYPE_PEM, untrusted_cert_pem)
store = X509Store()
store.add_cert(root_cert)
store.add_cert(intermediate_cert)
store_ctx = X509StoreContext(store, untrusted_cert)
store_ctx.verify_certificate()
