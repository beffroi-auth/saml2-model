<?php

// The configuration SimpleSAMLphp 2.5.3.1 distributes, then the settings of the service provider that differ from
// it, each with its reason in tests/Interop/simplesamlphp/README.md.
require '/var/simplesamlphp/config-dist/config.php.dist';

$config['secretsalt'] = 'saml2-model test service provider salt, not a secret';
$config['logging.handler'] = 'errorlog';
