<?php

// The hosted identity provider: its entity ID, its own signing pair and its authentication source, nothing else.
$metadata['http://localhost:8081/simplesaml/module.php/saml/idp/metadata'] = [
    'host' => '__DEFAULT__',
    'privatekey' => 'idp.pem',
    'certificate' => 'idp.crt',
    'auth' => 'example-userpass',
];

// The second configuration (SSP_SIGN_RESPONSE=false): the response is not signed, the assertion still is.
if (getenv('SSP_SIGN_RESPONSE') === 'false') {
    $metadata['http://localhost:8081/simplesaml/module.php/saml/idp/metadata']['saml20.sign.response'] = false;
}
