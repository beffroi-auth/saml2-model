<?php

declare(strict_types=1);

/*
 * Writes, with simplesamlphp/saml2 and the test keys of tests/Fixture/keys/, the documents of spec/model.md
 * section 9.5.1 into /out: a response with a signed assertion, the same response signed over it, a signed
 * AuthnRequest, a signed LogoutRequest, a signed LogoutResponse, and both metadata, unsigned and signed.
 *
 * Every value is fixed, IDs and times included, and RSA PKCS#1 v1.5 signs deterministically: two runs write the same
 * bytes. The windows are those SimpleSAMLphp's identity provider writes by default (modules/saml/src/IdP/SAML2.php):
 * NotBefore 30 s before the issue instant, 300 s of assertion.lifetime, 8 h of session.duration. The documents hold
 * together as one exchange, so that the model's validators accept them with a clock frozen at ISSUE_INSTANT.
 *
 * Run from the root of the repository (tests/Interop/simplesamlphp/README.md):
 *   docker run --rm -v "$PWD/tests/Interop/simplesamlphp/library:/app" -v "$PWD/tests/Fixture/keys:/keys:ro" \
 *       -v "$PWD/tests/Fixture/real:/out" -w /app ghcr.io/spomky-labs/phpqa:8.4 php produce.php
 */

require '/app/vendor/autoload.php';

use Composer\InstalledVersions;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Assertion;
use SAML2\AuthnRequest;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Constants;
use SAML2\LogoutRequest;
use SAML2\LogoutResponse;
use SAML2\Response;
use SAML2\Utils;
use SAML2\XML\md\EndpointType;
use SAML2\XML\md\EntityDescriptor;
use SAML2\XML\md\IDPSSODescriptor;
use SAML2\XML\md\IndexedEndpointType;
use SAML2\XML\md\SPSSODescriptor;
use SAML2\XML\saml\Issuer;
use SAML2\XML\saml\NameID;
use SAML2\XML\saml\SubjectConfirmation;
use SAML2\XML\saml\SubjectConfirmationData;

const PRODUCED_ON = '2026-09-30';
const ISSUE_INSTANT = '2026-09-30T12:00:00Z';

const IDP_ENTITY_ID = 'https://idp.example.org';
const IDP_SSO = 'https://idp.example.org/sso';
const IDP_SLO = 'https://idp.example.org/slo';
const SP_ENTITY_ID = 'https://sp.example.org';
const SP_ACS = 'https://sp.example.org/acs';
const SP_SLO = 'https://sp.example.org/slo';

const AUTHN_REQUEST_ID = '_ssp-lib-authnrequest-0001';
const RESPONSE_ID = '_ssp-lib-response-0001';
const ASSERTION_ID = '_ssp-lib-assertion-0001';
const LOGOUT_REQUEST_ID = '_ssp-lib-logoutrequest-0001';
const LOGOUT_RESPONSE_ID = '_ssp-lib-logoutresponse-0001';
const SESSION_INDEX = '_ssp-lib-session-0001';
const TRANSIENT_NAME_ID = '_ssp-lib-transient-0001';

ContainerSingleton::setContainer(new MockContainer());

$version = ltrim((string) InstalledVersions::getPrettyVersion('simplesamlphp/saml2'), 'v');
$now = (new DateTimeImmutable(ISSUE_INSTANT))->getTimestamp();

$idpKey = privateKey('/keys/idp-signing-key.pem');
$idpCertificate = (string) file_get_contents('/keys/idp-signing-certificate.pem');
$spKey = privateKey('/keys/sp-signing-key.pem');
$spCertificate = (string) file_get_contents('/keys/sp-signing-certificate.pem');

$authnRequest = new AuthnRequest();
$authnRequest->setId(AUTHN_REQUEST_ID);
$authnRequest->setIssueInstant($now - 5);
$authnRequest->setDestination(IDP_SSO);
$authnRequest->setIssuer(issuer(SP_ENTITY_ID));
$authnRequest->setAssertionConsumerServiceURL(SP_ACS);
$authnRequest->setProtocolBinding(Constants::BINDING_HTTP_POST);
$authnRequest->setNameIdPolicy(['Format' => Constants::NAMEID_TRANSIENT, 'AllowCreate' => true]);
$authnRequest->setSignatureKey($spKey);
$authnRequest->setCertificates([$spCertificate]);
write($version, 'authnrequest-signed', $authnRequest->toSignedXML());

$nameId = new NameID();
$nameId->setValue(TRANSIENT_NAME_ID);
$nameId->setFormat(Constants::NAMEID_TRANSIENT);
$nameId->setSPNameQualifier(SP_ENTITY_ID);

$confirmationData = new SubjectConfirmationData();
$confirmationData->setNotOnOrAfter($now + 300);
$confirmationData->setRecipient(SP_ACS);
$confirmationData->setInResponseTo(AUTHN_REQUEST_ID);
$confirmation = new SubjectConfirmation();
$confirmation->setMethod(Constants::CM_BEARER);
$confirmation->setSubjectConfirmationData($confirmationData);

$assertion = new Assertion();
$assertion->setId(ASSERTION_ID);
$assertion->setIssueInstant($now);
$assertion->setIssuer(issuer(IDP_ENTITY_ID));
$assertion->setNameId($nameId);
$assertion->setSubjectConfirmation([$confirmation]);
$assertion->setNotBefore($now - 30);
$assertion->setNotOnOrAfter($now + 300);
$assertion->setValidAudiences([SP_ENTITY_ID]);
$assertion->setAuthnInstant($now - 10);
$assertion->setSessionNotOnOrAfter($now - 10 + 8 * 60 * 60);
$assertion->setSessionIndex(SESSION_INDEX);
$assertion->setAuthnContextClassRef(Constants::AC_PASSWORD);
$assertion->setAttributeNameFormat(Constants::NAMEFORMAT_BASIC);
$assertion->setAttributes(['uid' => ['student'], 'eduPersonAffiliation' => ['member', 'student']]);
$assertion->setSignatureKey($idpKey);
$assertion->setCertificates([$idpCertificate]);

$response = new Response();
$response->setId(RESPONSE_ID);
$response->setIssueInstant($now);
$response->setDestination(SP_ACS);
$response->setInResponseTo(AUTHN_REQUEST_ID);
$response->setIssuer(issuer(IDP_ENTITY_ID));
$response->setAssertions([$assertion]);
write($version, 'response-signed-assertion', $response->toUnsignedXML());
$response->setSignatureKey($idpKey);
$response->setCertificates([$idpCertificate]);
write($version, 'response-signed-both', $response->toSignedXML());

$logoutRequest = new LogoutRequest();
$logoutRequest->setId(LOGOUT_REQUEST_ID);
$logoutRequest->setIssueInstant($now + 60);
$logoutRequest->setDestination(IDP_SLO);
$logoutRequest->setIssuer(issuer(SP_ENTITY_ID));
$logoutRequest->setNameId($nameId);
$logoutRequest->setSessionIndex(SESSION_INDEX);
$logoutRequest->setSignatureKey($spKey);
$logoutRequest->setCertificates([$spCertificate]);
write($version, 'logoutrequest-signed', $logoutRequest->toSignedXML());

$logoutResponse = new LogoutResponse();
$logoutResponse->setId(LOGOUT_RESPONSE_ID);
$logoutResponse->setIssueInstant($now + 61);
$logoutResponse->setDestination(SP_SLO);
$logoutResponse->setInResponseTo(LOGOUT_REQUEST_ID);
$logoutResponse->setIssuer(issuer(IDP_ENTITY_ID));
$logoutResponse->setSignatureKey($idpKey);
$logoutResponse->setCertificates([$idpCertificate]);
write($version, 'logoutresponse-signed', $logoutResponse->toSignedXML());

$idp = new IDPSSODescriptor();
$idp->setProtocolSupportEnumeration([Constants::NS_SAMLP]);
$idp->addKeyDescriptor(keyDescriptor($idpCertificate));
$idp->addSingleLogoutService(endpoint(Constants::BINDING_HTTP_REDIRECT, IDP_SLO));
$idp->setNameIDFormat([Constants::NAMEID_TRANSIENT]);
$idp->addSingleSignOnService(endpoint(Constants::BINDING_HTTP_REDIRECT, IDP_SSO));
$idpMetadata = new EntityDescriptor();
$idpMetadata->setEntityID(IDP_ENTITY_ID);
$idpMetadata->setID('_ssp-lib-idp-metadata-0001');
$idpMetadata->addRoleDescriptor($idp);
write($version, 'idp-metadata', $idpMetadata->toXML());
$idpMetadata->setSignatureKey($idpKey);
$idpMetadata->setCertificates([$idpCertificate]);
write($version, 'idp-metadata-signed', $idpMetadata->toXML());

$sp = new SPSSODescriptor();
$sp->setAuthnRequestsSigned(true);
$sp->setWantAssertionsSigned(true);
$sp->setProtocolSupportEnumeration([Constants::NS_SAMLP]);
$sp->addKeyDescriptor(keyDescriptor($spCertificate));
$sp->addSingleLogoutService(endpoint(Constants::BINDING_HTTP_REDIRECT, SP_SLO));
$sp->setNameIDFormat([Constants::NAMEID_TRANSIENT]);
$acs = new IndexedEndpointType();
$acs->setBinding(Constants::BINDING_HTTP_POST);
$acs->setLocation(SP_ACS);
$acs->setIndex(0);
$sp->addAssertionConsumerService($acs);
$spMetadata = new EntityDescriptor();
$spMetadata->setEntityID(SP_ENTITY_ID);
$spMetadata->setID('_ssp-lib-sp-metadata-0001');
$spMetadata->addRoleDescriptor($sp);
write($version, 'sp-metadata', $spMetadata->toXML());
$spMetadata->setSignatureKey($spKey);
$spMetadata->setCertificates([$spCertificate]);
write($version, 'sp-metadata-signed', $spMetadata->toXML());

printf(
    "written by simplesamlphp/saml2 %s with robrichards/xmlseclibs %s on PHP %s\n",
    $version,
    InstalledVersions::getPrettyVersion('robrichards/xmlseclibs'),
    PHP_VERSION,
);

function privateKey(string $path): XMLSecurityKey
{
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
    $key->loadKey((string) file_get_contents($path));

    return $key;
}

function issuer(string $entityId): Issuer
{
    $issuer = new Issuer();
    $issuer->setValue($entityId);

    return $issuer;
}

function endpoint(string $binding, string $location): EndpointType
{
    $endpoint = new EndpointType();
    $endpoint->setBinding($binding);
    $endpoint->setLocation($location);

    return $endpoint;
}

function keyDescriptor(string $certificatePem): SAML2\XML\md\KeyDescriptor
{
    $base64 = preg_replace('/-----[A-Z ]+-----|\s+/', '', $certificatePem);
    $keyDescriptor = Utils::createKeyDescriptor($base64);
    $keyDescriptor->setUse('signing');

    return $keyDescriptor;
}

function write(string $version, string $document, DOMElement $root): void
{
    $file = sprintf('/out/simplesamlphp-saml2-%s-%s-%s.xml', $version, $document, PRODUCED_ON);
    file_put_contents($file, $root->ownerDocument->saveXML());
    echo 'wrote ', basename($file), "\n";
}
