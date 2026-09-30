<?php

// The configuration SimpleSAMLphp 2.5.3.1 distributes, then the settings of the identity provider that differ from
// it, each with its reason in tests/Interop/simplesamlphp/README.md.
require '/var/simplesamlphp/config-dist/config.php.dist';

$config['secretsalt'] = 'saml2-model test identity provider salt, not a secret';
$config['logging.handler'] = 'errorlog';
$config['module.enable']['exampleauth'] = true;
$config['enable.saml20-idp'] = true;
$config['session.cookie.name'] = 'IdPSimpleSAMLSessionID';
$config['session.phpsession.cookiename'] = 'IdPSimpleSAML';
$config['session.authtoken.cookiename'] = 'IdPSimpleSAMLAuthToken';
