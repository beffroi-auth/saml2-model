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
