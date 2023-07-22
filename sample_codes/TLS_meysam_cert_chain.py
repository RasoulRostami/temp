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
MIIFYjCCBEqgAwIBAgIQd70NbNs2+RrqIQ/E8FjTDTANBgkqhkiG9w0BAQsFADBX                                                                                                                                                     
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE                                                                                                                                                     
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIwMDYx                                                                                                                                                     
OTAwMDA0MloXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT                                                                                                                                                     
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFIx                                                                                                                                                     
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAthECix7joXebO9y/lD63
ladAPKH9gvl9MgaCcfb2jH/76Nu8ai6Xl6OMS/kr9rH5zoQdsfnFl97vufKj6bwS
iV6nqlKr+CMny6SxnGPb15l+8Ape62im9MZaRw1NEDPjTrETo8gYbEvs/AmQ351k
KSUjB6G00j0uYODP0gmHu81I8E3CwnqIiru6z1kZ1q+PsAewnjHxgsHA3y6mbWwZ
DrXYfiYaRQM9sHmklCitD38m5agI/pboPGiUU+6DOogrFZYJsuB6jC511pzrp1Zk
j5ZPaK49l8KEj8C8QMALXL32h7M1bKwYUH+E4EzNktMg6TO8UpmvMrUpsyUqtEj5
cuHKZPfmghCN6J3Cioj6OGaK/GP5Afl4/Xtcd/p2h/rs37EOeZVXtL0m79YB0esW
CruOC7XFxYpVq9Os6pFLKcwZpDIlTirxZUTQAs6qzkm06p98g7BAe+dDq6dso499
iYH6TKX/1Y7DzkvgtdizjkXPdsDtQCv9Uw+wp9U7DbGKogPeMa3Md+pvez7W35Ei
Eua++tgy/BBjFFFy3l3WFpO9KWgz7zpm7AeKJt8T11dleCfeXkkUAKIAf5qoIbap
sZWwpbkNFhHax2xIPEDgfg1azVY80ZcFuctL7TlLnMQ/0lUTbiSw1nH69MG6zO0b
9f6BQdgAmD06yK56mDcYBZUCAwEAAaOCATgwggE0MA4GA1UdDwEB/wQEAwIBhjAP
BgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTkrysmcRorSCeFL1JmLO/wiRNxPjAf
BgNVHSMEGDAWgBRge2YaRQ2XyolQL30EzTSo//z9SzBgBggrBgEFBQcBAQRUMFIw
JQYIKwYBBQUHMAGGGWh0dHA6Ly9vY3NwLnBraS5nb29nL2dzcjEwKQYIKwYBBQUH
MAKGHWh0dHA6Ly9wa2kuZ29vZy9nc3IxL2dzcjEuY3J0MDIGA1UdHwQrMCkwJ6Al
oCOGIWh0dHA6Ly9jcmwucGtpLmdvb2cvZ3NyMS9nc3IxLmNybDA7BgNVHSAENDAy
MAgGBmeBDAECATAIBgZngQwBAgIwDQYLKwYBBAHWeQIFAwIwDQYLKwYBBAHWeQIF
AwMwDQYJKoZIhvcNAQELBQADggEBADSkHrEoo9C0dhemMXoh6dFSPsjbdBZBiLg9
NR3t5P+T4Vxfq7vqfM/b5A3Ri1fyJm9bvhdGaJQ3b2t6yMAYN/olUazsaL+yyEn9
WprKASOshIArAoyZl+tJaox118fessmXn1hIVw41oeQa1v1vg4Fv74zPl6/AhSrw
9U5pCZEt4Wi4wStz6dTZ/CLANx8LZh1J7QJVj2fhMtfTJr9w4z30Z209fOU0iOMy
+qduBmpvvYuR7hZL6Dupszfnw0Skfths18dG9ZKb59UhvmaSGZRVbNQpsg3BZlvi
d0lIKO2d1xozclOzgjXPYovJJIultzkMu34qQb9Sz/yilrbCgj8=
-----END CERTIFICATE-----
"""
)
intermediate_cert_pem = b(
    """-----BEGIN CERTIFICATE-----                                                                                                                                                                                          
MIIFljCCA36gAwIBAgINAgO8U1lrNMcY9QFQZjANBgkqhkiG9w0BAQsFADBHMQsw                                                                                                                                                     
CQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExMQzEU                                                                                                                                                     
MBIGA1UEAxMLR1RTIFJvb3QgUjEwHhcNMjAwODEzMDAwMDQyWhcNMjcwOTMwMDAw                                                                                                                                                     
MDQyWjBGMQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZp                                                                                                                                                     
Y2VzIExMQzETMBEGA1UEAxMKR1RTIENBIDFDMzCCASIwDQYJKoZIhvcNAQEBBQAD                                                                                                                                                     
ggEPADCCAQoCggEBAPWI3+dijB43+DdCkH9sh9D7ZYIl/ejLa6T/belaI+KZ9hzp                                                                                                                                                     
kgOZE3wJCor6QtZeViSqejOEH9Hpabu5dOxXTGZok3c3VVP+ORBNtzS7XyV3NzsX                                                                                                                                                     
lOo85Z3VvMO0Q+sup0fvsEQRY9i0QYXdQTBIkxu/t/bgRQIh4JZCF8/ZK2VWNAcm                                                                                                                                                     
BA2o/X3KLu/qSHw3TT8An4Pf73WELnlXXPxXbhqW//yMmqaZviXZf5YsBvcRKgKA                                                                                                                                                     
gOtjGDxQSYflispfGStZloEAoPtR28p3CwvJlk/vcEnHXG0g/Zm0tOLKLnf9LdwL                                                                                                                                                     
tmsTDIwZKxeWmLnwi/agJ7u2441Rj72ux5uxiZ0CAwEAAaOCAYAwggF8MA4GA1Ud                                                                                                                                                     
DwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0T                                                                                                                                                     
AQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUinR/r4XN7pXNPZzQ4kYU83E1HScwHwYD                                                                                                                                                     
VR0jBBgwFoAU5K8rJnEaK0gnhS9SZizv8IkTcT4waAYIKwYBBQUHAQEEXDBaMCYG                                                                                                                                                     
CCsGAQUFBzABhhpodHRwOi8vb2NzcC5wa2kuZ29vZy9ndHNyMTAwBggrBgEFBQcw                                                                                                                                                     
AoYkaHR0cDovL3BraS5nb29nL3JlcG8vY2VydHMvZ3RzcjEuZGVyMDQGA1UdHwQt                                                                                                                                                     
MCswKaAnoCWGI2h0dHA6Ly9jcmwucGtpLmdvb2cvZ3RzcjEvZ3RzcjEuY3JsMFcG                                                                                                                                                     
A1UdIARQME4wOAYKKwYBBAHWeQIFAzAqMCgGCCsGAQUFBwIBFhxodHRwczovL3Br                                                                                                                                                     
aS5nb29nL3JlcG9zaXRvcnkvMAgGBmeBDAECATAIBgZngQwBAgIwDQYJKoZIhvcN                                                                                                                                                     
AQELBQADggIBAIl9rCBcDDy+mqhXlRu0rvqrpXJxtDaV/d9AEQNMwkYUuxQkq/BQ                                                                                                                                                     
cSLbrcRuf8/xam/IgxvYzolfh2yHuKkMo5uhYpSTld9brmYZCwKWnvy15xBpPnrL                                                                                                                                                     
RklfRuFBsdeYTWU0AIAaP0+fbH9JAIFTQaSSIYKCGvGjRFsqUBITTcFTNvNCCK9U                                                                                                                                                     
+o53UxtkOCcXCb1YyRt8OS1b887U7ZfbFAO/CVMkH8IMBHmYJvJh8VNS/UKMG2Yr                                                                                                                                                     
PxWhu//2m+OBmgEGcYk1KCTd4b3rGS3hSMs9WYNRtHTGnXzGsYZbr8w0xNPM1IER                                                                                                                                                     
lQCh9BIiAfq0g3GvjLeMcySsN1PCAJA/Ef5c7TaUEDu9Ka7ixzpiO2xj2YC/WXGs                                                                                                                                                     
Yye5TBeg2vZzFb8q3o/zpWwygTMD0IZRcZk0upONXbVRWPeyk+gB9lm+cZv9TSjO                                                                                                                                                     
z23HFtz30dZGm6fKa+l3D/2gthsjgx0QGtkJAITgRNOidSOzNIb2ILCkXhAd4FJG                                                                                                                                                     
AJ2xDx8hcFH1mt0G/FX0Kw4zd8NLQsLxdxP8c4CU6x+7Nz/OAipmsHMdMqUybDKw                                                                                                                                                     
juDEI/9bfU1lcKwrmz3O2+BtjjKAvpafkmO8l7tdufThcV4q5O8DIrGKZTqPwJNl                                                                                                                                                     
1IXNDw9bg1kWRxYtnCQ6yICmJhSFm/Y3m6xv+cXDBlHz4n/FsRC6UfTd                                                                                                                                                             
-----END CERTIFICATE-----
"""
)
untrusted_cert_pem = b(
    """-----BEGIN CERTIFICATE-----                                                                                                                                                                                          
MIIEhzCCA2+gAwIBAgIQOkzLa5rVdt8Q6At1nf9JNjANBgkqhkiG9w0BAQsFADBG                                                                                                                                                     
MQswCQYDVQQGEwJVUzEiMCAGA1UEChMZR29vZ2xlIFRydXN0IFNlcnZpY2VzIExM                                                                                                                                                     
QzETMBEGA1UEAxMKR1RTIENBIDFDMzAeFw0yMzA3MDMwODI0MzBaFw0yMzA5MjUw                                                                                                                                                     
ODI0MjlaMBkxFzAVBgNVBAMTDnd3dy5nb29nbGUuY29tMFkwEwYHKoZIzj0CAQYI                                                                                                                                                     
KoZIzj0DAQcDQgAEXzXbTFh9VADgOmO3Fd7HIUR+C3pXK5DKK3WZsvSvAKdfy3sc                                                                                                                                                     
mnAk92yC3UXQcQ6DYQzL+4aIc+be193ZFzSan6OCAmcwggJjMA4GA1UdDwEB/wQE                                                                                                                                                     
AwIHgDATBgNVHSUEDDAKBggrBgEFBQcDATAMBgNVHRMBAf8EAjAAMB0GA1UdDgQW                                                                                                                                                     
BBTB485ljFeLW3iZOCUs492zAAjowTAfBgNVHSMEGDAWgBSKdH+vhc3ulc09nNDi                                                                                                                                                     
RhTzcTUdJzBqBggrBgEFBQcBAQReMFwwJwYIKwYBBQUHMAGGG2h0dHA6Ly9vY3Nw                                                                                                                                                     
LnBraS5nb29nL2d0czFjMzAxBggrBgEFBQcwAoYlaHR0cDovL3BraS5nb29nL3Jl                                                                                                                                                     
cG8vY2VydHMvZ3RzMWMzLmRlcjAZBgNVHREEEjAQgg53d3cuZ29vZ2xlLmNvbTAh                                                                                                                                                     
BgNVHSAEGjAYMAgGBmeBDAECATAMBgorBgEEAdZ5AgUDMDwGA1UdHwQ1MDMwMaAv                                                                                                                                                     
oC2GK2h0dHA6Ly9jcmxzLnBraS5nb29nL2d0czFjMy9tb1ZEZklTaWEyay5jcmww                                                                                                                                                     
ggEEBgorBgEEAdZ5AgQCBIH1BIHyAPAAdgC3Pvsk35xNunXyOcW6WPRsXfxCz3qf                                                                                                                                                     
NcSeHQmBJe20mQAAAYkbEWKBAAAEAwBHMEUCIQD2rHhorOp5V1+vsYMnDCBRUKKZ                                                                                                                                                     
bfW2OTUwPvb4j86V7AIgF0QyWv9z84n08CmfG7oY3BDMJNAtO99o7cnXP0/mQLwA                                                                                                                                                     
dgCt9776fP8QyIudPZwePhhqtGcpXc+xDCTKhYY069yCigAAAYkbEWKwAAAEAwBH                                                                                                                                                     
MEUCIQDocHv2qjmXP1NVtS7Wjfe5uk/EUDwHvZ4ETbkjBCE9XAIgBEmst+hOULNC                                                                                                                                                     
4cX8FcuRmcfXWgCH5hT2mWM3QGNF0UAwDQYJKoZIhvcNAQELBQADggEBAKh/LX8t                                                                                                                                                     
Yi8LonbiKcOR+JpLai5q40JqlXs22pssMDSR6O/Fmg8LdSy3s2PvV/JldV0Nhxjj                                                                                                                                                     
rNplXICj9ZBtU5HOdZHX6HH3nEXiCeu6TLDoAz4EHyOnKbn31OsbZFo+spHLzhSF                                                                                                                                                     
ieJvsMCruI+hNse74NyMkapWjdP1/4fJahHUiX3X3e9JldnHLaaoDfbyF1Yv2jaj                                                                                                                                                     
jRuW5nkj8prPYnQbTWwrBpJpQTN0YVolibzY9q1N8iZZrp3PTRoPWNGZmTsD0JpF                                                                                                                                                     
GHHgZJXQvTV+ldwsDHIn417uJpI+nASxvZ0cjddraLiMJSdAmgpAA70ayfAhyDXT                                                                                                                                                     
4+7ehVbqI693sV0=                                                                                                                                                                                                     
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
