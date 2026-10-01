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

// The model's identity provider, once the exchange has written its metadata (tests/Interop/simplesamlphp/exchange.php):
// the XML the model's MetadataWriter wrote, read by SimpleSAMLphp's own parser, as it is. The service provider that
// logs in there, for-model, carries its own settings (authsources.php).
$model = '/var/simplesamlphp/model/model-idp-metadata.xml';
if (is_file($model)) {
    foreach (\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString((string) file_get_contents($model)) as $entityId => $parser) {
        $metadata[$entityId] = $parser->getMetadata20IdP() ?? [];
    }
}
