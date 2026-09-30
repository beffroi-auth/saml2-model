<?php

// The service provider of http://localhost:8082, as its metadata publishes it.
$metadata['http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp'] = [
    'AssertionConsumerService' => [
        [
            'index' => 0,
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            'Location' => 'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp',
        ],
    ],
    'SingleLogoutService' => [
        [
            'Binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
            'Location' => 'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-logout.php/default-sp',
        ],
    ],
    'certificate' => 'sp.crt',
];
