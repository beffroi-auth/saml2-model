<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Support;

use function base64_encode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\CanonicalizationMethod;
use Beffroi\Xml\Core\Canonicalizer;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\InclusiveNamespaces;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\DigestAlgorithm;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\SignatureAlgorithm;
use Beffroi\Xml\Dsig\Signer;
use function chunk_split;
use function file_get_contents;
use function file_put_contents;
use LogicException;
use function preg_match;
use function preg_quote;
use function rtrim;
use function sprintf;
use function str_replace;
use function substr_count;

/**
 * The response fixtures of sections 9.2 and 9.3 (story #7), each a variant of one valid response with the one change
 * that the case names, signed with the test keys of tests/Fixture/keys/ through Dsig's Signer wherever the attack
 * needs a valid signature, then written as files under tests/Fixture/ (hostile/response-*, behaviour/response-*).
 * RSA PKCS#1 v1.5 is deterministic: the same keys build the same bytes, which the test of this class checks against
 * the committed files. The command that writes them is in tests/Fixture/hostile/response-README.md.
 *
 * The valid response answers the request _request of the service provider https://sp.example.com/saml at its
 * assertion consumer service https://sp.example.com/saml/acs, from the identity provider https://idp.example.com/saml,
 * at 2026-09-30T11:59:59Z, the assertion issued a second earlier; the tests freeze the clock at 12:00:00Z.
 */
final class ResponseFixtureBuilder
{
    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    private const string EXCLUSIVE = 'http://www.w3.org/2001/10/xml-exc-c14n#';

    private const string SUCCESS = '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>';

    /**
     * The response's own Issuer, told from the assertion's by its indentation.
     */
    private const string RESPONSE_ISSUER = "\n  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>";

    private const string ASSERTION_ISSUER = '<saml:Issuer>https://idp.example.com/saml</saml:Issuer>';

    private const string DESTINATION = ' Destination="https://sp.example.com/saml/acs"';

    private const string RESPONSE_IN_RESPONSE_TO = 'Destination="https://sp.example.com/saml/acs" InResponseTo="_request"';

    private const string CONFIRMATION_IN_RESPONSE_TO = 'Recipient="https://sp.example.com/saml/acs" InResponseTo="_request"';

    /**
     * Every fixture, its path under tests/Fixture/ mapped to its bytes.
     *
     * @return array<string, string>
     */
    public static function fixtures(): array
    {
        return [...self::behaviour(), ...self::wrapping(), ...self::envelope(), ...self::status()];
    }

    /**
     * Writes every fixture under $directory, tests/Fixture/ of the repository.
     */
    public static function write(string $directory): void
    {
        foreach (self::fixtures() as $path => $bytes) {
            if (file_put_contents($directory . '/' . $path, $bytes) === false) {
                throw new LogicException(sprintf('%s could not be written.', $path));
            }
        }
    }

    /**
     * §9.3: the three coverages of M-2, and the responses the validator accepts.
     *
     * @return array<string, string>
     */
    private static function behaviour(): array
    {
        $base = self::base();
        $prefixed = self::replace(
            '<saml:AttributeValue>',
            '<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">',
            self::replace(
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"',
                'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema"',
                $base,
            ),
        );

        return [
            'behaviour/response-signed-assertion-accepted.xml' => self::signed($base, ['_assertion']),
            'behaviour/response-signed-response-accepted.xml' => self::signed($base, ['_response']),
            'behaviour/response-signed-both-accepted.xml' => self::signed($base, ['_assertion', '_response']),
            'behaviour/response-unsolicited-accepted.xml' => self::signed(
                self::replace(
                    self::CONFIRMATION_IN_RESPONSE_TO,
                    'Recipient="https://sp.example.com/saml/acs"',
                    self::replace(
                        self::RESPONSE_IN_RESPONSE_TO,
                        'Destination="https://sp.example.com/saml/acs"',
                        $base,
                    ),
                ),
                ['_assertion'],
            ),
            'behaviour/response-without-destination-accepted.xml' => self::signed(
                self::replace(self::DESTINATION, '', $base),
                ['_assertion'],
            ),
            'behaviour/response-without-issuer-accepted.xml' => self::signed(
                self::replace(self::RESPONSE_ISSUER, '', $base),
                ['_assertion'],
            ),
            'behaviour/response-same-assertion-id-another-issuer-accepted.xml' => self::signed(
                self::replace('https://idp.example.com/saml', 'https://other-idp.example.com/saml', $base, 2),
                ['_assertion'],
            ),
            'behaviour/response-extensions-with-content-accepted.xml' => self::signed(
                self::replace(
                    "\n  <samlp:Status>",
                    "\n  <samlp:Extensions><ext:Hint xmlns:ext=\"urn:example:extension\">not read</ext:Hint>"
                    . "</samlp:Extensions>\n  <samlp:Status>",
                    $base,
                ),
                ['_assertion'],
            ),
            'behaviour/response-signed-both-prefix-list-accepted.xml' => self::signed(
                self::prefixListed(self::signed($prefixed, ['_assertion'])),
                ['_response'],
            ),
        ];
    }

    /**
     * §9.2 rows 1 to 11: the message-level wrapping corpus, and the keys of M-3.
     *
     * @return array<string, string>
     */
    private static function wrapping(): array
    {
        $base = self::base();
        $unsigned = self::element($base, 'saml:Assertion');
        $signed = self::element(self::signed($base, ['_assertion']), 'saml:Assertion');
        $signature = self::element($signed, 'ds:Signature');
        $evil = self::replace(
            '>_7a2f4c1d9e<',
            '>_attacker<',
            self::replace('ID="_assertion"', 'ID="_evil"', $unsigned),
        );
        $bothSigned = self::signed($base, ['_assertion', '_response']);
        $second = self::replace('ID="_assertion"', 'ID="_assertion2"', $unsigned);

        return [
            'hostile/response-assertion-in-extensions-same-id-refused.xml' => self::declared(self::inExtensions(
                self::replace($unsigned, $signed, $base),
                self::replace('>_7a2f4c1d9e<', '>_attacker<', $unsigned),
            )),
            'hostile/response-assertion-in-extensions-another-id-refused.xml' => self::unsigned(self::inExtensions(
                self::replace($unsigned, $signed, $base),
                $evil,
            )),
            'hostile/response-assertion-in-extensions-signature-copied-refused.xml' => self::unsigned(self::inExtensions(
                self::replace($unsigned, $signed, $base),
                self::replace(self::ASSERTION_ISSUER, self::ASSERTION_ISSUER . $signature, $evil),
            )),
            'hostile/response-assertion-in-extensions-signed-response-refused.xml' => self::unsigned(
                self::inExtensions($bothSigned, $evil),
            ),
            'hostile/response-two-signed-assertions-refused.xml' => self::signed(
                self::replace($unsigned, $unsigned . "\n  " . $second, $base),
                ['_assertion', '_assertion2'],
            ),
            'hostile/response-unsigned-assertion-before-signed-refused.xml' => self::unsigned(
                self::replace($unsigned, $evil . "\n  " . $signed, $base),
            ),
            'hostile/response-unsigned-assertion-after-signed-refused.xml' => self::unsigned(
                self::replace($unsigned, $signed . "\n  " . $evil, $base),
            ),
            'hostile/response-assertion-in-advice-refused.xml' => self::signed(
                self::replace(
                    "</saml:Conditions>\n",
                    "</saml:Conditions>\n    <saml:Advice>"
                    . self::replace('ID="_evil"', 'ID="_advised"', $evil)
                    . "</saml:Advice>\n",
                    $base,
                ),
                ['_assertion'],
            ),
            'hostile/response-assertion-in-signature-object-refused.xml' => self::unsigned(self::replace(
                $unsigned,
                self::replace(
                    self::ASSERTION_ISSUER,
                    self::ASSERTION_ISSUER
                        . self::replace(
                            '</ds:Signature>',
                            '<ds:Object>' . $unsigned . '</ds:Object></ds:Signature>',
                            $signature,
                        ),
                    $evil,
                ),
                $base,
            )),
            'hostile/response-unsigned-refused.xml' => self::unsigned($base),
            'hostile/response-assertion-signature-fails-under-signed-response-refused.xml' => self::signed(
                self::replace('>_7a2f4c1d9e<', '>_attacker<', self::signed($base, ['_assertion'])),
                ['_response'],
            ),
            'hostile/response-assertion-signed-by-another-key-refused.xml' => self::signed(
                $base,
                ['_assertion'],
                'sp',
                self::file('keys/sp-signing-certificate.pem'),
            ),
        ];
    }

    /**
     * §9.2 rows 12 to 17, 21, 22, 25, 26 and 29, section 6.1 steps 2 and 6: the envelope around the assertion.
     *
     * @return array<string, string>
     */
    private static function envelope(): array
    {
        $base = self::base();
        $unsigned = self::element($base, 'saml:Assertion');
        $withoutIssuer = self::replace(self::RESPONSE_ISSUER, '', $base);
        $signedAssertion = self::signed($base, ['_assertion']);
        $assertionSignature = self::element($signedAssertion, 'ds:Signature');
        $bothSigned = self::signed($base, ['_assertion', '_response']);
        $responseSignature = self::element($bothSigned, 'ds:Signature');

        return [
            'hostile/response-destination-another-url-refused.xml' => self::destination('https://attacker.example.com/saml/acs'),
            'hostile/response-signed-without-destination-refused.xml' => self::signed(
                self::replace(self::DESTINATION, '', $base),
                ['_assertion', '_response'],
            ),
            'hostile/response-destination-trailing-slash-refused.xml' => self::destination('https://sp.example.com/saml/acs/'),
            'hostile/response-destination-host-case-refused.xml' => self::destination('https://SP.example.com/saml/acs'),
            'hostile/response-destination-percent-encoded-refused.xml' => self::destination('https://sp.example.com/saml/%61cs'),
            'hostile/response-destination-relative-refused.xml' => self::destination('saml/acs'),
            'hostile/response-recipient-another-url-refused.xml' => self::signed(
                self::replace(
                    'Recipient="https://sp.example.com/saml/acs"',
                    'Recipient="https://attacker.example.com/saml/acs"',
                    $base,
                ),
                ['_assertion'],
            ),
            'hostile/response-without-recipient-refused.xml' => self::signed(
                self::replace(' Recipient="https://sp.example.com/saml/acs"', '', $base),
                ['_assertion'],
            ),
            'hostile/response-in-response-to-another-request-refused.xml' => self::signed(
                self::replace(
                    self::RESPONSE_IN_RESPONSE_TO,
                    'Destination="https://sp.example.com/saml/acs" InResponseTo="_another"',
                    $base,
                ),
                ['_assertion', '_response'],
            ),
            'hostile/response-confirmation-in-response-to-another-request-refused.xml' => self::signed(
                self::replace(
                    self::CONFIRMATION_IN_RESPONSE_TO,
                    'Recipient="https://sp.example.com/saml/acs" InResponseTo="_another"',
                    $base,
                ),
                ['_assertion'],
            ),
            'hostile/response-in-response-to-not-an-ncname-refused.xml' => self::signed(
                self::replace(
                    self::RESPONSE_IN_RESPONSE_TO,
                    'Destination="https://sp.example.com/saml/acs" InResponseTo="1request"',
                    $base,
                ),
                ['_assertion'],
            ),
            'hostile/response-audience-another-sp-refused.xml' => self::signed(
                self::replace(
                    '<saml:Audience>https://sp.example.com/saml</saml:Audience>',
                    '<saml:Audience>https://other-sp.example.com/saml</saml:Audience>',
                    $base,
                ),
                ['_assertion'],
            ),
            'hostile/response-status-responder-with-assertion-refused.xml' => self::signed(
                self::replace(
                    self::SUCCESS,
                    '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>',
                    $base,
                ),
                ['_assertion'],
            ),
            'hostile/response-success-without-assertion-refused.xml' => self::unsigned(
                self::replace("\n  " . $unsigned, '', $base),
            ),
            'hostile/response-encrypted-assertion-refused.xml' => self::unsigned(self::replace(
                $unsigned,
                '<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"'
                . ' Type="http://www.w3.org/2001/04/xmlenc#Element"/></saml:EncryptedAssertion>',
                $base,
            )),
            'hostile/response-issuer-name-qualifier-refused.xml' => self::signed(
                self::replace(
                    self::RESPONSE_ISSUER,
                    "\n  <saml:Issuer NameQualifier=\"https://idp.example.com/saml\">https://idp.example.com/saml</saml:Issuer>",
                    $base,
                ),
                ['_assertion', '_response'],
            ),
            'hostile/response-issuer-another-entity-refused.xml' => self::signed(
                self::replace(
                    self::RESPONSE_ISSUER,
                    "\n  <saml:Issuer>https://other-idp.example.com/saml</saml:Issuer>",
                    $base,
                ),
                ['_assertion', '_response'],
            ),
            'hostile/response-signed-without-issuer-refused.xml' => self::signed(
                $withoutIssuer,
                ['_assertion', '_response'],
            ),
            'hostile/response-two-issuers-refused.xml' => self::signed(
                self::replace(self::RESPONSE_ISSUER, self::RESPONSE_ISSUER . self::RESPONSE_ISSUER, $base),
                ['_assertion'],
            ),
            'hostile/response-two-assertions-without-issuer-refused.xml' => self::unsigned(self::replace(
                $unsigned,
                $unsigned . "\n  " . self::replace('ID="_assertion"', 'ID="_assertion2"', $unsigned),
                $withoutIssuer,
            )),
            'hostile/response-status-after-assertion-refused.xml' => self::unsigned(self::replace(
                self::element($signedAssertion, 'saml:Assertion'),
                self::element($signedAssertion, 'saml:Assertion') . "\n  " . self::element($base, 'samlp:Status'),
                self::replace("\n  " . self::element($base, 'samlp:Status'), '', $signedAssertion),
            )),
            'hostile/response-signature-before-issuer-refused.xml' => self::unsigned(self::replace(
                self::RESPONSE_ISSUER . $responseSignature,
                "\n  " . $responseSignature . self::RESPONSE_ISSUER,
                $bothSigned,
            )),
            'hostile/response-assertion-signature-before-issuer-refused.xml' => self::unsigned(self::replace(
                self::ASSERTION_ISSUER . $assertionSignature,
                $assertionSignature . self::ASSERTION_ISSUER,
                $signedAssertion,
            )),
            'hostile/response-assertion-two-signatures-refused.xml' => self::unsigned(
                self::replace($assertionSignature, $assertionSignature . $assertionSignature, $signedAssertion),
            ),
            'hostile/response-version-2-1-refused.xml' => self::signed(
                self::replace('ID="_response" Version="2.0"', 'ID="_response" Version="2.1"', $base),
                ['_assertion'],
            ),
            'hostile/response-without-version-refused.xml' => self::signed(
                self::replace('ID="_response" Version="2.0"', 'ID="_response"', $base),
                ['_assertion'],
            ),
            'hostile/response-without-id-refused.xml' => self::signed(
                self::replace(' ID="_response"', '', $base),
                ['_assertion'],
            ),
            'hostile/response-without-issue-instant-refused.xml' => self::signed(
                self::replace(' IssueInstant="2026-09-30T11:59:59Z"', '', $base),
                ['_assertion'],
            ),
        ];
    }

    /**
     * §9.2 row 22, §9.3 row 14, M-13, section 6.1 steps 2 and 4: the status, and the responses that carry a failure.
     *
     * @return array<string, string>
     */
    private static function status(): array
    {
        $failure = self::failure();
        $signedFailure = self::signed($failure, ['_response']);
        $responder = '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">';
        $authnFailed = '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>';

        return [
            'behaviour/response-status-responder-authn-failed-refused.xml' => self::unsigned($failure),
            'behaviour/response-status-responder-authn-failed-signed-refused.xml' => $signedFailure,
            'behaviour/response-status-requester-without-issuer-refused.xml' => self::unsigned(self::replace(
                self::element($failure, 'samlp:Status'),
                '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>',
                self::replace(self::RESPONSE_ISSUER, '', $failure),
            )),
            'behaviour/response-status-responder-unknown-second-level-refused.xml' => self::failureWith(
                $authnFailed,
                '<samlp:StatusCode Value="urn:example:status:PasswordExpired"/>',
            ),
            'hostile/response-status-signed-then-altered-refused.xml' => self::declared(self::replace(
                'status:AuthnFailed',
                'status:RequestDenied',
                $signedFailure,
            )),
            'hostile/response-status-in-response-to-another-request-refused.xml' => self::unsigned(self::replace(
                self::RESPONSE_IN_RESPONSE_TO,
                'Destination="https://sp.example.com/saml/acs" InResponseTo="_another"',
                $failure,
            )),
            'hostile/response-status-unknown-code-refused.xml' => self::failureWith(
                $responder,
                '<samlp:StatusCode Value="urn:example:status:Fine">',
            ),
            'hostile/response-status-code-without-value-refused.xml' => self::failureWith(
                $responder,
                '<samlp:StatusCode>',
            ),
            'hostile/response-status-message-before-code-refused.xml' => self::unsigned(self::replace(
                "\n    <samlp:StatusMessage>The password of jdoe@example.com is wrong</samlp:StatusMessage>",
                '',
                self::replace(
                    '<samlp:Status>',
                    '<samlp:Status><samlp:StatusMessage>The password of jdoe@example.com is wrong</samlp:StatusMessage>',
                    $failure,
                ),
            )),
            'hostile/response-status-two-second-level-codes-refused.xml' => self::failureWith(
                $authnFailed,
                $authnFailed . $authnFailed,
            ),
            'hostile/response-status-second-level-without-value-refused.xml' => self::failureWith(
                $authnFailed,
                '<samlp:StatusCode/>',
            ),
        ];
    }

    /**
     * §9.2 rows 1 to 4: $response with its assertion moved into a samlp:Extensions before its status, and $inPlace
     * where the assertion was.
     */
    private static function inExtensions(string $response, string $inPlace): string
    {
        $assertion = self::element($response, 'saml:Assertion');

        return self::replace(
            "\n  <samlp:Status>",
            "\n  <samlp:Extensions>" . $assertion . "</samlp:Extensions>\n  <samlp:Status>",
            self::replace($assertion, $inPlace, $response),
        );
    }

    /**
     * §9.2 rows 12 and 13: the valid response with the Destination $url, the assertion and the response signed.
     */
    private static function destination(string $url): string
    {
        return self::signed(
            self::replace(self::DESTINATION, sprintf(' Destination="%s"', $url), self::base()),
            ['_assertion', '_response'],
        );
    }

    /**
     * §9.3 row 14: the valid response with a status Responder, AuthnFailed at the second level, a StatusMessage and a
     * StatusDetail, and no assertion (SAML Profiles §4.1.4.2), unsigned.
     */
    private static function failure(): string
    {
        $base = self::base();

        return self::replace(
            "\n  " . self::element($base, 'saml:Assertion'),
            '',
            self::replace(
                self::element($base, 'samlp:Status'),
                <<<'XML'
                    <samlp:Status>
                        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
                          <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:AuthnFailed"/>
                        </samlp:StatusCode>
                        <samlp:StatusMessage>The password of jdoe@example.com is wrong</samlp:StatusMessage>
                        <samlp:StatusDetail><ext:Trace xmlns:ext="urn:example:extension">not read</ext:Trace></samlp:StatusDetail>
                      </samlp:Status>
                    XML,
                $base,
            ),
        );
    }

    /**
     * The failure with $search replaced by $replace, unsigned.
     */
    private static function failureWith(string $search, string $replace): string
    {
        return self::unsigned(self::replace($search, $replace, self::failure()));
    }

    /**
     * The valid response, unsigned: one assertion of a persistent NameID, a bearer confirmation, one audience, an
     * authentication statement and one attribute; the XML declaration is written by the serializer.
     */
    private static function base(): string
    {
        return <<<'XML'
            <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_response" Version="2.0" IssueInstant="2026-09-30T11:59:59Z" Destination="https://sp.example.com/saml/acs" InResponseTo="_request">
              <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
              <saml:Assertion ID="_assertion" Version="2.0" IssueInstant="2026-09-30T11:59:58Z">
                <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
                <saml:Subject>
                  <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">_7a2f4c1d9e</saml:NameID>
                  <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                    <saml:SubjectConfirmationData NotOnOrAfter="2026-09-30T12:04:58Z" Recipient="https://sp.example.com/saml/acs" InResponseTo="_request"/>
                  </saml:SubjectConfirmation>
                </saml:Subject>
                <saml:Conditions NotBefore="2026-09-30T11:59:28Z" NotOnOrAfter="2026-09-30T12:04:58Z">
                  <saml:AudienceRestriction>
                    <saml:Audience>https://sp.example.com/saml</saml:Audience>
                  </saml:AudienceRestriction>
                </saml:Conditions>
                <saml:AuthnStatement AuthnInstant="2026-09-30T11:59:57Z" SessionIndex="_session">
                  <saml:AuthnContext>
                    <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
                  </saml:AuthnContext>
                </saml:AuthnStatement>
                <saml:AttributeStatement>
                  <saml:Attribute Name="urn:oid:0.9.2342.19200300.100.1.3" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri" FriendlyName="mail">
                    <saml:AttributeValue>jdoe@example.com</saml:AttributeValue>
                  </saml:Attribute>
                </saml:AttributeStatement>
              </saml:Assertion>
            </samlp:Response>
            XML;
    }

    /**
     * The document, loaded then serialized as the serializer writes it, unsigned.
     */
    private static function unsigned(string $xml): string
    {
        return new Serializer()->serialize(SamlLoader::create()->load($xml));
    }

    /**
     * The bytes of a document the loader refuses, or one whose signature no longer holds, with the XML declaration
     * the serializer writes in front of the others.
     */
    private static function declared(string $xml): string
    {
        return preg_match('~\A<\?xml ~', $xml) === 1
            ? $xml
            : "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" . $xml . "\n";
    }

    /**
     * The document with an enveloped signature over each element of $ids, in order, after its saml:Issuer when it
     * has one and first otherwise (SAML Core §5.4.1): an assertion before the response that carries it.
     *
     * @param list<string> $ids
     * @param 'idp'|'sp' $key the identity provider's test key, or the service provider's, which the metadata of the
     *                        identity provider does not list
     * @param ?string $certificatePem the certificate the signatures carry in their KeyInfo, none by default
     */
    private static function signed(string $xml, array $ids, string $key = 'idp', ?string $certificatePem = null): string
    {
        $document = SamlLoader::create()->load($xml);
        $signer = new Signer(SamlLoader::create());
        $issuer = new Name(Saml::ASSERTION, 'Issuer');
        foreach ($ids as $id) {
            $document = $signer->sign(
                $document,
                $id,
                PrivateKey::fromPem(self::file(sprintf('keys/%s-signing-key.pem', $key))),
                after: Children::named($document->elementById($id), $issuer) === [] ? null : $issuer,
                certificatePem: $certificatePem,
            );
        }

        return new Serializer()->serialize($document);
    }

    /**
     * §9.3 row 4: the assertion's signature of $signed made again with an InclusiveNamespaces naming the prefix xs
     * on its exclusive transform, the digest computed over the assertion where it stands, where the response declares
     * xs: Signer writes no PrefixList (dsig.md section 6.2 step 5), so the reference, its digest and the signature
     * over SignedInfo are made here, with Core's canonicalizer and the test key.
     */
    private static function prefixListed(string $signed): string
    {
        $listed = self::replace(
            sprintf('<ds:Transform Algorithm="%s"/>', self::EXCLUSIVE),
            sprintf(
                '<ds:Transform Algorithm="%1$s"><ec:InclusiveNamespaces xmlns:ec="%1$s" PrefixList="xs"/></ds:Transform>',
                self::EXCLUSIVE,
            ),
            $signed,
        );
        // each Document is held while its elements are read: Core finds the document of a node through it
        $document = SamlLoader::create()->load($listed);
        $assertion = Children::one($document->root(), new Name(Saml::ASSERTION, 'Assertion'));
        $canonicalizer = new Canonicalizer();
        $digested = self::replace(
            self::text($listed, 'ds:DigestValue'),
            base64_encode(DigestAlgorithm::Sha256->hash($canonicalizer->canonicalize(
                $assertion,
                CanonicalizationMethod::Exclusive,
                InclusiveNamespaces::fromPrefixList('xs'),
                [Children::one($assertion, new Name(self::DSIG, 'Signature'))],
            )->bytes)),
            $listed,
        );
        $document = SamlLoader::create()->load($digested);
        $signedInfo = Children::one(
            Children::one(
                Children::one($document->root(), new Name(Saml::ASSERTION, 'Assertion')),
                new Name(self::DSIG, 'Signature'),
            ),
            new Name(self::DSIG, 'SignedInfo'),
        );
        $value = PrivateKey::fromPem(self::file('keys/idp-signing-key.pem'))->sign(
            $canonicalizer->canonicalize($signedInfo, CanonicalizationMethod::Exclusive)->bytes,
            SignatureAlgorithm::RsaSha256,
        );

        return self::replace(
            self::text($digested, 'ds:SignatureValue'),
            rtrim(chunk_split(base64_encode($value), 76, "\n"), "\n"),
            $digested,
        );
    }

    /**
     * The first element $qualifiedName of $xml, from its start tag to its end tag, as written: never one that holds
     * another of its name.
     */
    private static function element(string $xml, string $qualifiedName): string
    {
        $name = preg_quote($qualifiedName, '~');
        if (preg_match(sprintf('~<%1$s[\s>].*?</%1$s>~s', $name), $xml, $match) !== 1) {
            throw new LogicException(sprintf('No %s in the document.', $qualifiedName));
        }

        return $match[0];
    }

    /**
     * The text of the first element $qualifiedName of $xml, as written.
     */
    private static function text(string $xml, string $qualifiedName): string
    {
        $name = preg_quote($qualifiedName, '~');
        if (preg_match(sprintf('~<%1$s>([^<]*)</%1$s>~', $name), $xml, $match) !== 1) {
            throw new LogicException(sprintf('No %s in the document.', $qualifiedName));
        }

        return $match[1];
    }

    /**
     * $subject with $search replaced, which occurs exactly $count times: a variant that changes nothing is a
     * mistake of the builder, never a fixture.
     */
    private static function replace(string $search, string $replace, string $subject, int $count = 1): string
    {
        if (substr_count($subject, $search) !== $count) {
            throw new LogicException(sprintf('The document holds %s other than %d times.', $search, $count));
        }

        return str_replace($search, $replace, $subject);
    }

    private static function file(string $path): string
    {
        $bytes = file_get_contents(__DIR__ . '/../Fixture/' . $path);
        if ($bytes === false) {
            throw new LogicException(sprintf('%s could not be read.', $path));
        }

        return $bytes;
    }
}
