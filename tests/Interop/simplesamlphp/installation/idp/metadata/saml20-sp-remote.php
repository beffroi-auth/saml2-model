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

// The model's service provider, once the exchange has written its metadata (tests/Interop/simplesamlphp/exchange.php):
// the XML the model's MetadataWriter wrote, read by SimpleSAMLphp's own parser, the one its XML metadata sources and
// its metarefresh module use. Two settings are added to what the XML says, both for this service provider alone:
// sign.logout, since SimpleSAMLphp signs no logout message by default and the model refuses an unsigned one (M-2,
// finding F-1); validate.logout, since SimpleSAMLphp otherwise accepts a logout message whose signature failed as
// an unsigned one (finding F-3), and its acceptance would prove nothing. validate.authnrequest comes from the
// AuthnRequestsSigned="true" of the XML.
$model = '/var/simplesamlphp/model/model-sp-metadata.xml';
if (is_file($model)) {
    foreach (\SimpleSAML\Metadata\SAMLParser::parseDescriptorsString((string) file_get_contents($model)) as $entityId => $parser) {
        $metadata[$entityId] = ['sign.logout' => true, 'validate.logout' => true] + ($parser->getMetadata20SP() ?? []);
    }
}
