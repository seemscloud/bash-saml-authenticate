```bash
#!/bin/bash
 
HOST="example.localdomain"
HOSTNAME="https://example.localdomain:443"
 
LOGIN="USERNAME"
PASSWD="PASSWORD"
 
CRED="${LOGIN}:${PASSWD}"
CRED_BASE64=$(echo -n "${CRED}" | base64)
 
REQ_STS_LOCATION=$(curl -X GET --silent -i -k "${HOSTNAME}/webservices/Service/API" \
-c cookie.jar \
-H "Host ${HOST}")
 
echo "${REQ_STS_LOCATION}" > A_RespFromSP_GetLocation.wsdl
 
HTTP_CODE=$(echo "${REQ_STS_LOCATION}" | grep -Po "HTTP/1.1 \K[0-9]*")
 
if [[ -z "${HTTP_CODE}" ]] ; then
    echo "(1) Empty response.." && exit
elif [[ "${HTTP_CODE}" == "302" ]] ; then
    echo "(1) STS location found.. HTTP Code: ${HTTP_CODE}"
else
    echo "(1) Failed get STS location.. HTTP Code: ${HTTP_CODE}"
    echo "---------------------------------------------------------------------"
    echo "(1) ${REQ_STS_LOCATION}" && exit
fi
 
STS_LOCATION=$(echo "${REQ_STS_LOCATION}" | grep -Po "Location: \K[a-zA-Z0-9://.:=?%\-&]*")
 
WSDL_SAML_LOGIN="<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"><soap:Body><RequestSecurityToken xmlns=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"><TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0</TokenType><RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</RequestType></RequestSecurityToken></soap:Body></soap:Envelope>"
 
echo -ne "${WSDL_SAML_LOGIN}" > B_ReqToSTS_SAMLLogin.wsdl
 
REQ_SAML_LOGIN=$(curl -X POST --silent -i -k "${STS_LOCATION}" \
-H 'Content-Type: application/soap+xml; charset=utf-8; action="http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue"' \
-H 'Accept-Encoding: gzip, deflate' \
-H "Authorization: Basic ${CRED_BASE64}" \
-H "Host: ${HOST}" \
--data @B_ReqToSTS_SAMLLogin.wsdl)
 
echo -ne "${REQ_SAML_LOGIN}" > B_RespFromSTS_SAMLLogin.wsdl
 
HTTP_CODE=$(echo "${REQ_SAML_LOGIN}" | grep -Po "HTTP/1.1 \K[1-9][0-9]*")
 
if [[ -z "${HTTP_CODE}" ]] ; then
    echo "(2) Empty response.." && exit
elif [[ "${HTTP_CODE}" == "200" ]] ; then
    echo "(2) Authorization successfully.. HTTP Code: ${HTTP_CODE}"
else
    echo "(2) Authorization failed.. HTTP Code: ${HTTP_CODE}"
    echo "---------------------------------------------------------------------"
    echo "(2) ${REQ_SAML_LOGIN}" && exit
fi
 
ID=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "\KID_[a-zA-Z0-9-]*" | uniq)
SignatureValue=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=SignatureValue).*>\K.*(?=</dsig:SignatureValue)")
Modulus=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=Modulus).*>\K.*(?=</dsig:Modulus)")
IssueInstant=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "IssueInstant=\"\K[a-zA-Z0-9-.:]*")
Created=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=Created).*>\K.*(?=</wsu:Created)")
Expires=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=Expires).*>\K.*(?=</wsu:Expires)")
AuthnInstant=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "AuthnInstant=\"\K[a-zA-Z0-9-.:]*")
NotBefore=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "NotBefore=\"\K[a-zA-Z0-9-.:]*")
NotOnOrAfter=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "NotOnOrAfter=\"\K[a-zA-Z0-9-.:]*")
Exponent=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=Exponent).*>\K.*(?=</dsig:Exponent)")
NameID=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=NameID).*>\K.*(?=</saml:NameID)")
Issuer=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=Issuer).*>\K.*(?=</saml:Issuer)")
DigestValue=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=DigestValue).*>\K.*(?=</dsig:DigestValue)")
KeySize=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=KeySize).*>\K.*(?=</wst:KeySize)")
KeyType=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=KeyType).*>\K.*(?=</wst:KeyType)")
AuthnContextClassRef=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "(?<=AuthnContextClassRef).*>\K.*(?=</saml:AuthnContextClassRef)")
SubjectConfirmationMethod=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "Method=\"\K[a-zA-Z0-9-.:]*")
AssertionXMLNSSAML=$(echo -n "${REQ_SAML_LOGIN}" | grep -Po "Assertion xmlns:saml=\"\K[a-zA-Z0-9-.:]*")
 
TIME_NOW=$(date +%Y-%m-%dT%H:%M:%S.%6NZ -u)
 
_UUID=$(uuidgen -t)
 
WSDL_SAML_RESPONSE_TEMPLATE="<?xml version=\"1.0\" encoding=\"utf-8\"?><Response xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" ID=\"ID_${_UUID}\" Version=\"2.0\" IssueInstant=\"${TIME_NOW}\" xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\"><Status><StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\" /></Status><saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" Version=\"2.0\" ID=\"${ID}\" IssueInstant=\"${IssueInstant}\"><saml:Issuer>${Issuer}</saml:Issuer><dsig:Signature xmlns:dsig=\"http://www.w3.org/2000/09/xmldsig#\"><dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#WithComments\" /><dsig:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\" /><dsig:Reference URI=\"#${ID}\"><dsig:Transforms><dsig:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><dsig:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\" /></dsig:Transforms><dsig:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" /><dsig:DigestValue>${DigestValue}</dsig:DigestValue></dsig:Reference></dsig:SignedInfo><dsig:SignatureValue>${SignatureValue}</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyValue><dsig:RSAKeyValue><dsig:Modulus>${Modulus}</dsig:Modulus><dsig:Exponent>${Exponent}</dsig:Exponent></dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature><saml:Subject><saml:NameID NameQualifier=\"urn:picketlink:identity-federation\">${NameID}</saml:NameID><saml:SubjectConfirmation Method=\"${SubjectConfirmationMethod}\" /></saml:Subject><saml:Conditions NotBefore=\"${NotBefore}\" NotOnOrAfter=\"${NotOnOrAfter}\" /><saml:AuthnStatement AuthnInstant=\"${AuthnInstant}\"><saml:AuthnContext><saml:AuthnContextClassRef>${AuthnContextClassRef}</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></Response>"
 
WSDL_SAML_RESPONSE=$(echo -ne "${WSDL_SAML_RESPONSE_TEMPLATE}" | base64 -w 9999999 | sed -E "s/\+/%2B/g" | sed -E "s/\=/%3D/g")
 
echo -ne "${WSDL_SAML_RESPONSE_TEMPLATE}" > C_ReqToSP_SAMLResponse.wsdl
echo -ne "SAMLResponse=${WSDL_SAML_RESPONSE}" > C_ReqToSP_SAMLResponse.encoded
 
REQ_SAML_RESPONSE=$(curl -X POST --silent -i -k "${HOSTNAME}/webservices/Service/API" \
-b cookie.jar \
-c cookie.jar \
-H 'Content-Type: application/x-www-form-urlencoded' \
-H "Host: ${HOST}" \
-H 'Expect: 100-continue' \
--data @C_ReqToSP_SAMLResponse.encoded)
 
echo -ne "${REQ_SAML_RESPONSE}" > C_RespFromSP_SAMLResponse.wsdl
 
HTTP_CODE=$(echo "${REQ_SAML_RESPONSE}" | grep -Po "HTTP/1.1 \K[2-9][0-9]*")
 
if [[ -z "${HTTP_CODE}" ]] ; then
    echo "(3) Empty response.." && exit
elif [[ "${HTTP_CODE}" == "302" ]] ; then
    echo "(3) SAML Response send successfully.. HTTP Code: ${HTTP_CODE}"
else
    echo "(3) Failed send SAML Response.. HTTP Code: ${HTTP_CODE}"
    echo "---------------------------------------------------------------------"
    echo "(3) ${REQ_SAML_RESPONSE}"
    exit
fi
 
WSDL_REPORT_EXAMPLE="EXAMPLE XML"         # Change Me!
 
echo "${WSDL_REPORT_EXAMPLE}" > D_ReqToSP_Example.wsdl
 
REQ_REPORT_EXAMPLE=$(curl -X POST --silent -i -k "${HOSTNAME}/webservices/Service/API" \
-b cookie.jar \
-H 'Content-Type: text/xml; charset=utf-8' \
-H 'Accept-Language: en-GB' \
-H 'SOAPAction: "getReport"' \
-H "Host: ${HOST}" \
-H 'Accept-Encoding: gzip, deflate' \
--data @D_ReqToSP_Example.wsdl)
 
echo "${REQ_REPORT_EXAMPLE}" > D_RespFromSP_Example.wsdl
 
HTTP_CODE=$(echo "${REQ_REPORT_EXAMPLE}" | grep -Po "HTTP/1.1 \K[2-9][0-9]*")
 
if [[ -z "${HTTP_CODE}" ]] ; then
    echo "(4) Empty response.." && exit
elif [[ "${HTTP_CODE}" == "200" ]] ; then
    echo "(4) Example report generated successfully.. HTTP Code: ${HTTP_CODE}"
else
    echo "(4) Failed generate example report .. HTTP Code: ${HTTP_CODE}"
    echo "---------------------------------------------------------------------"
    echo "(4) ${\}"
    exit
fi
```
