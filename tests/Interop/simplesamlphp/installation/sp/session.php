<?php

// What the service provider for-model holds of its session, as JSON: the proof, for the exchange, that it accepted
// the response of the model's identity provider and with which values. Mounted into public/ by compose.yaml.
require '/var/simplesamlphp/src/_autoload.php';

$as = new \SimpleSAML\Auth\Simple('for-model');
header('Content-Type: application/json');
if (!$as->isAuthenticated()) {
    http_response_code(401);
    echo json_encode(['authenticated' => false]);
    return;
}
$nameId = $as->getAuthData('saml:sp:NameID');
echo json_encode([
    'authenticated' => true,
    'idp' => $as->getAuthData('saml:sp:IdP'),
    'nameId' => $nameId instanceof \SAML2\XML\saml\NameID
        ? ['value' => $nameId->getValue(), 'format' => $nameId->getFormat(), 'spNameQualifier' => $nameId->getSPNameQualifier()]
        : null,
    'sessionIndex' => $as->getAuthData('saml:sp:SessionIndex'),
    'attributes' => $as->getAttributes(),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
