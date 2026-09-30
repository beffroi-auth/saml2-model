<?php

// The authentication sources SimpleSAMLphp 2.5.3.1 distributes, default-sp given its entity ID, its identity
// provider, its own signing pair, and signed authentication and logout requests.
require '/var/simplesamlphp/config-dist/authsources.php.dist';

$config['default-sp']['entityID'] = 'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp';
$config['default-sp']['idp'] = 'http://localhost:8081/simplesaml/module.php/saml/idp/metadata';
$config['default-sp']['privatekey'] = 'sp.pem';
$config['default-sp']['certificate'] = 'sp.crt';
$config['default-sp']['sign.authnrequest'] = true;
$config['default-sp']['sign.logout'] = true;

// A second service provider, for the exchange with the model's identity provider (exchange.php): default-sp's
// settings, its own entity ID, the model's identity provider, its single logout service published for HTTP-POST
// too, where the model answers with a signed LogoutResponse, and validate.logout, since SimpleSAMLphp otherwise
// accepts a logout message whose signature failed as an unsigned one (finding F-3).
$config['for-model'] = [
    'saml:SP',
    'entityID' => 'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/for-model',
    'idp' => 'http://localhost:8083/model/idp',
    'privatekey' => 'sp.pem',
    'certificate' => 'sp.crt',
    'sign.authnrequest' => true,
    'sign.logout' => true,
    'validate.logout' => true,
    'SingleLogoutServiceBinding' => [
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
        'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
    ],
];
