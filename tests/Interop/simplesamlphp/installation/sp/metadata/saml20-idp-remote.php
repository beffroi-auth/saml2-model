<?php

// The identity provider of http://localhost:8081, as its metadata publishes it.
$metadata['http://localhost:8081/simplesaml/module.php/saml/idp/metadata'] = [
    'SingleSignOnService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8081/simplesaml/module.php/saml/idp/singleSignOnService',
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8081/simplesaml/module.php/saml/idp/singleLogout',
        ],
    ],
    'certificate' => 'idp.crt',
];
