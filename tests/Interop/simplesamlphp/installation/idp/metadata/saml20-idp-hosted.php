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

// The third configuration (SSP_EXCHANGE=true), the exchange with the model: the single sign-on and single logout
// services published for HTTP-POST too, at the same locations, since the model posts its signed messages there and
// leaves HTTP-Redirect and its detached signature to saml2-bindings. Off by default, so that the metadata phase 1
// captured stays what a run of capture.sh serves.
if (getenv('SSP_EXCHANGE') === 'true') {
    $bindings = [
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ];
    $metadata['http://localhost:8081/simplesaml/module.php/saml/idp/metadata']['SingleSignOnServiceBinding'] = $bindings;
    $metadata['http://localhost:8081/simplesaml/module.php/saml/idp/metadata']['SingleLogoutServiceBinding'] = $bindings;
}
