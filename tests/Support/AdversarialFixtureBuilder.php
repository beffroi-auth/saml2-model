<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Support;

use function array_map;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Serializer;
use Beffroi\Xml\Dsig\PrivateKey;
use Beffroi\Xml\Dsig\Signer;
use function file_get_contents;
use function file_put_contents;
use function implode;
use LogicException;
use function mb_substr;
use function preg_match;
use function preg_quote;
use function preg_replace;
use function preg_replace_callback;
use function sprintf;
use function str_repeat;
use function str_replace;
use function substr_count;
use function trim;

/**
 * The fixtures of the adversarial pass of section 9.8 (story #12): each row of section 3 attacked with inputs the
 * corpus of 9.2 and 9.3 does not list, every attempt a file whatever its outcome, hostile/adversarial-<attempt>-refused.xml
 * or behaviour/adversarial-<attempt>-accepted.xml, each a variant of one valid message with the change its name says,
 * signed with the test keys of tests/Fixture/keys/ through Dsig's Signer wherever the attack needs a valid signature.
 * RSA PKCS#1 v1.5 is deterministic: the same keys build the same bytes, which the adversarial test checks against the
 * committed files. The command that writes them is in tests/Fixture/hostile/adversarial-README.md.
 *
 * Every message is issued at 2026-09-30T11:59:59Z, and the tests freeze the clock at 12:00:00Z: the response answers
 * the request _request of the service provider https://sp.example.com/saml at its assertion consumer service
 * https://sp.example.com/saml/acs, from the identity provider https://idp.example.com/saml; the AuthnRequest goes the
 * other way, to https://idp.example.com/saml/sso; the LogoutRequest goes from the identity provider to the service
 * provider's https://sp.example.com/saml/slo, and the LogoutResponse back to https://idp.example.com/saml/slo.
 */
final class AdversarialFixtureBuilder
{
    private const string PROTOCOL = 'urn:oasis:names:tc:SAML:2.0:protocol';

    private const string ASSERTION = 'urn:oasis:names:tc:SAML:2.0:assertion';

    private const string SUCCESS = '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>';

    /**
     * The response's own Issuer, told from the assertion's by its indentation.
     */
    private const string RESPONSE_ISSUER = "\n  <saml:Issuer>https://idp.example.com/saml</saml:Issuer>";

    private const string ASSERTION_ISSUER = '<saml:Issuer>https://idp.example.com/saml</saml:Issuer>';

    /**
     * The assertion's Issuer in the unsigned response, told from the response's by its indentation.
     */
    private const string ASSERTION_ISSUER_IN_RESPONSE = "\n    <saml:Issuer>https://idp.example.com/saml</saml:Issuer>";

    private const string DESTINATION = 'Destination="https://sp.example.com/saml/acs"';

    private const string RECIPIENT = 'Recipient="https://sp.example.com/saml/acs"';

    private const string AUDIENCE = '<saml:Audience>https://sp.example.com/saml</saml:Audience>';

    private const string NAME_ID = '<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">_7a2f4c1d9e</saml:NameID>';

    private const string CONFIRMATION_DATA = '<saml:SubjectConfirmationData NotOnOrAfter="2026-09-30T12:04:58Z" Recipient="https://sp.example.com/saml/acs" InResponseTo="_request"/>';

    private const string ATTRIBUTE_VALUE = '<saml:AttributeValue>jdoe@example.com</saml:AttributeValue>';

    private const string STATUS = "\n  <samlp:Status>";

    private const string ACS = 'AssertionConsumerServiceURL="https://sp.example.com/saml/acs"';

    private const string XML_ATTRIBUTES = ' xml:base="https://attacker.example.com/" xml:lang="fr"';

    /**
     * Every fixture, its path under tests/Fixture/ mapped to its bytes.
     *
     * @return array<string, string>
     */
    public static function fixtures(): array
    {
        return [
            ...self::wrapping(),
            ...self::namespaces(),
            ...self::xmlAttributes(),
            ...self::identifiers(),
            ...self::times(),
            ...self::booleans(),
            ...self::uris(),
            ...self::bounds(),
            ...self::commentsAndInstructions(),
            ...self::otherRows(),
        ];
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
     * Section 3 row 1, M-1, M-4: the signed assertion moved to the places the 2012 study names and those it does not,
     * an unsigned assertion where the consumer reads, the signature copied or the response signed over the original.
     *
     * @return array<string, string>
     */
    private static function wrapping(): array
    {
        $signed = self::signed(self::response(), ['_assertion']);
        $original = self::element($signed, 'saml:Assertion');
        $evil = self::evil();
        $copied = self::withSignatureOf($evil, $original);
        $both = self::signed(self::response(), ['_assertion', '_response']);

        return [
            self::refused('response-assertion-in-status') => self::unsigned(
                self::replace(self::SUCCESS, self::SUCCESS . $original, self::replace($original, $evil, $signed)),
            ),
            self::refused('response-assertion-in-status-code') => self::unsigned(self::replace(
                self::SUCCESS,
                self::replace('/>', '>', self::SUCCESS) . $original . '</samlp:StatusCode>',
                self::replace($original, $evil, $signed),
            )),
            self::refused('response-assertion-in-status-message') => self::unsigned(self::replace(
                self::SUCCESS,
                self::SUCCESS . '<samlp:StatusMessage>' . $original . '</samlp:StatusMessage>',
                self::replace($original, $evil, $signed),
            )),
            self::refused('response-assertion-in-status-detail') => self::unsigned(
                self::inStatusDetail(self::replace($original, $evil, $signed), $original),
            ),
            self::refused('response-assertion-in-status-detail-signature-copied') => self::unsigned(
                self::inStatusDetail(self::replace($original, $copied, $signed), $original),
            ),
            self::refused('response-assertion-in-status-detail-signed-response') => self::declared(self::inStatusDetail(
                self::replace(self::element($both, 'saml:Assertion'), $evil, $both),
                self::element($both, 'saml:Assertion'),
            )),
            self::accepted('response-unsigned-assertion-in-status-detail') => self::unsigned(
                self::inStatusDetail($signed, $evil),
            ),
            self::refused('response-assertion-in-subject-confirmation-data') => self::unsigned(self::replace(
                $original,
                self::replace(
                    self::CONFIRMATION_DATA,
                    self::replace('/>', '>', self::CONFIRMATION_DATA) . $original . '</saml:SubjectConfirmationData>',
                    $evil,
                ),
                $signed,
            )),
            self::refused('response-assertion-in-subject-confirmation-data-signature-copied') => self::unsigned(
                self::replace(
                    $original,
                    self::replace(
                        self::CONFIRMATION_DATA,
                        self::replace('/>', '>', self::CONFIRMATION_DATA)
                        . $original
                        . '</saml:SubjectConfirmationData>',
                        $copied,
                    ),
                    $signed,
                ),
            ),
            self::refused('response-assertion-in-conditions') => self::unsigned(self::replace(
                $original,
                self::replace(
                    "\n    </saml:Conditions>",
                    $original . "\n    </saml:Conditions>",
                    $evil,
                ),
                $signed,
            )),
            self::refused('response-assertion-in-attribute') => self::unsigned(self::replace(
                $original,
                self::replace(
                    self::ATTRIBUTE_VALUE,
                    self::ATTRIBUTE_VALUE . $original,
                    $evil,
                ),
                $signed,
            )),
            self::refused('response-assertion-in-attribute-value') => self::unsigned(self::replace(
                $original,
                self::replace(
                    self::ATTRIBUTE_VALUE,
                    '<saml:AttributeValue>' . $original . '</saml:AttributeValue>',
                    $evil,
                ),
                $signed,
            )),
            self::refused('response-assertion-in-extensions-under-another-prefix') => self::unsigned(self::replace(
                self::STATUS,
                sprintf(
                    "\n  <p:Extensions xmlns:p=\"%s\">%s</p:Extensions>%s",
                    self::PROTOCOL,
                    $original,
                    self::STATUS,
                ),
                self::replace($original, $evil, $signed),
            )),
            self::refused('response-assertion-in-extensions-in-the-default-namespace') => self::unsigned(self::replace(
                self::STATUS,
                sprintf("\n  <Extensions xmlns=\"%s\">%s</Extensions>%s", self::PROTOCOL, $original, self::STATUS),
                self::replace($original, $evil, $signed),
            )),
            self::accepted('response-unsigned-assertion-in-extensions-next-to-the-signed-one') => self::unsigned(
                self::replace(
                    self::STATUS,
                    "\n  <samlp:Extensions>" . $evil . '</samlp:Extensions>' . self::STATUS,
                    $signed,
                ),
            ),
            self::accepted('response-unsigned-assertion-in-the-key-info-of-the-signature') => self::unsigned(
                self::replace(
                    '</ds:SignatureValue></ds:Signature>',
                    '</ds:SignatureValue><ds:KeyInfo>' . $evil . '</ds:KeyInfo></ds:Signature>',
                    $signed,
                ),
            ),
            self::refused('response-assertion-in-the-issuer-of-the-response') => self::declared(self::replace(
                self::RESPONSE_ISSUER,
                "\n  <saml:Issuer>https://idp.example.com/saml" . $evil . '</saml:Issuer>',
                $signed,
            )),
            self::refused('response-unsigned-assertion-before-the-status') => self::unsigned(
                self::replace(self::STATUS, "\n  " . $evil . self::STATUS, $signed),
            ),
        ];
    }

    /**
     * Section 3 rows 1 and 11, M-5: the SAML elements under the default namespace, another prefix, swapped prefixes, a
     * prefix rebound on a child, a SAML name in another namespace, attributes in a namespace next to the real ones.
     *
     * @return array<string, string>
     */
    private static function namespaces(): array
    {
        $base = self::response();
        $assertion = self::element($base, 'saml:Assertion');
        $unprefixed = self::replace(
            '<Assertion ',
            sprintf('<Assertion xmlns="%s" ', self::ASSERTION),
            str_replace(['<saml:', '</saml:'], ['<', '</'], $assertion),
        );
        $defaults = str_replace(
            ['<samlp:', '</samlp:', sprintf('xmlns:samlp="%s" xmlns:saml="%s"', self::PROTOCOL, self::ASSERTION)],
            ['<', '</', sprintf('xmlns="%s"', self::PROTOCOL)],
            self::replace(
                self::RESPONSE_ISSUER,
                sprintf("\n  <Issuer xmlns=\"%s\">https://idp.example.com/saml</Issuer>", self::ASSERTION),
                self::replace($assertion, $unprefixed, $base),
            ),
        );
        $signed = self::signed($base, ['_assertion']);
        $unsignedMetadata = self::identityProviderMetadata();

        return [
            self::accepted('response-default-namespaces') => self::signed($defaults, ['_assertion']),
            self::accepted('response-assertion-namespace-under-another-prefix') => self::signed(
                str_replace(['<saml:', '</saml:', 'xmlns:saml='], ['<a:', '</a:', 'xmlns:a='], $base),
                ['_assertion'],
            ),
            self::accepted('response-prefixes-swapped') => self::signed(
                str_replace(
                    ['samlp:', 'saml:', "\u{0}", 'xmlns:samlp', 'xmlns:saml=', "\u{1}"],
                    ["\u{0}", 'samlp:', 'saml:', "\u{1}", 'xmlns:samlp=', 'xmlns:saml'],
                    $base,
                ),
                ['_assertion'],
            ),
            self::accepted('response-namespaces-declared-again-on-every-element') => self::signed(
                self::replace(
                    sprintf(
                        '<samlp:Response xmlns:samlp="%1$s" xmlns:saml="%2$s" xmlns:samlp="%1$s" xmlns:saml="%2$s"',
                        self::PROTOCOL,
                        self::ASSERTION,
                    ),
                    sprintf('<samlp:Response xmlns:samlp="%s" xmlns:saml="%s"', self::PROTOCOL, self::ASSERTION),
                    self::onEveryStartTag(
                        $base,
                        sprintf(' xmlns:samlp="%s" xmlns:saml="%s"', self::PROTOCOL, self::ASSERTION),
                    ),
                ),
                ['_assertion'],
            ),
            self::refused('response-prefix-rebound-on-the-subject') => self::signed(
                self::replace('<saml:Subject>', '<saml:Subject xmlns:saml="urn:example:not-saml">', $base),
                ['_assertion'],
            ),
            self::refused('response-prefix-rebound-on-the-name-id') => self::signed(
                self::replace('<saml:NameID ', '<saml:NameID xmlns:saml="urn:example:not-saml" ', $base),
                ['_assertion'],
            ),
            self::refused('response-prefix-rebound-on-the-audience-restriction') => self::signed(
                self::replace(
                    '<saml:AudienceRestriction>',
                    '<saml:AudienceRestriction xmlns:saml="urn:example:not-saml">',
                    $base,
                ),
                ['_assertion'],
            ),
            self::refused('response-assertion-in-the-saml-1-namespace') => self::unsigned(self::renamed(
                $base,
                'saml:Assertion',
                'saml1:Assertion xmlns:saml1="urn:oasis:names:tc:SAML:1.0:assertion"',
                'saml1:Assertion',
            )),
            self::refused('response-assertion-namespace-in-upper-case') => self::unsigned(self::renamed(
                $base,
                'saml:Assertion',
                'up:Assertion xmlns:up="URN:OASIS:NAMES:TC:SAML:2.0:ASSERTION"',
                'up:Assertion',
            )),
            self::refused('response-assertion-in-no-namespace') => self::unsigned(
                self::renamed($signed, 'saml:Assertion', 'Assertion xmlns=""', 'Assertion'),
            ),
            self::refused('response-status-in-the-assertion-namespace') => self::unsigned(
                self::renamed($signed, 'samlp:Status', 'saml:Status', 'saml:Status'),
            ),
            self::refused('response-issuer-in-the-protocol-namespace') => self::unsigned(self::replace(
                self::RESPONSE_ISSUER,
                "\n  <samlp:Issuer>https://idp.example.com/saml</samlp:Issuer>",
                $signed,
            )),
            self::refused('response-recipient-in-a-namespace') => self::signed(
                self::replace(self::RECIPIENT, 'saml:' . self::RECIPIENT, $base),
                ['_assertion'],
            ),
            self::accepted('response-attributes-in-a-namespace-next-to-the-real-ones') => self::signed(
                self::replace(
                    '<saml:NameID ',
                    '<saml:NameID x:Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" ',
                    self::replace(
                        self::ASSERTION_ISSUER_IN_RESPONSE,
                        "\n    <saml:Issuer saml:Format=\"urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified\">"
                        . 'https://idp.example.com/saml</saml:Issuer>',
                        self::replace(
                            self::CONFIRMATION_DATA,
                            self::replace(
                                '/>',
                                ' x:Recipient="https://attacker.example.com/acs" x:InResponseTo="_attacker"/>',
                                self::CONFIRMATION_DATA,
                            ),
                            self::replace(
                                'InResponseTo="_request">',
                                'InResponseTo="_request" xmlns:x="urn:example:attributes"'
                                . ' x:Destination="https://attacker.example.com/acs" x:InResponseTo="_attacker">',
                                $base,
                            ),
                        ),
                    ),
                ),
                ['_assertion'],
            ),
            self::accepted('authn-request-default-namespaces') => self::unsigned(str_replace(
                [
                    '<samlp:',
                    sprintf('xmlns:samlp="%s" xmlns:saml="%s"', self::PROTOCOL, self::ASSERTION),
                    '<saml:Issuer>',
                    '</saml:Issuer>',
                    '</samlp:',
                ],
                [
                    '<',
                    sprintf('xmlns="%s"', self::PROTOCOL),
                    sprintf('<Issuer xmlns="%s">', self::ASSERTION),
                    '</Issuer>',
                    '</',
                ],
                self::authnRequest(),
            )),
            self::refused('authn-request-issuer-in-the-protocol-namespace') => self::unsigned(str_replace(
                ['<saml:Issuer>', '</saml:Issuer>'],
                ['<samlp:Issuer>', '</samlp:Issuer>'],
                self::authnRequest(),
            )),
            self::accepted('metadata-default-namespace') => self::unsigned(str_replace(
                ['<md:', '</md:', 'xmlns:md='],
                ['<', '</', 'xmlns='],
                $unsignedMetadata,
            )),
            self::refused('metadata-key-info-in-a-namespace-one-character-off') => self::unsigned(self::replace(
                '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">',
                '<ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig">',
                $unsignedMetadata,
            )),
        ];
    }

    /**
     * Section 3 rows 6 and 7, M-8: xml:base and xml:lang on every element, which the model never reads, and a relative
     * URI that an xml:base would resolve to the expected one.
     *
     * @return array<string, string>
     */
    private static function xmlAttributes(): array
    {
        $base = self::response();

        return [
            self::accepted('response-xml-base-and-lang-on-every-element') => self::signed(
                self::onEveryStartTag($base, self::XML_ATTRIBUTES),
                ['_assertion'],
            ),
            self::accepted('response-signed-both-xml-base-and-lang-on-every-element') => self::signed(
                self::onEveryStartTag($base, self::XML_ATTRIBUTES),
                ['_assertion', '_response'],
            ),
            self::refused('response-relative-destination-under-an-xml-base') => self::signed(
                self::replace(self::DESTINATION, 'xml:base="https://sp.example.com/saml/" Destination="acs"', $base),
                ['_assertion', '_response'],
            ),
            self::refused('response-relative-recipient-under-an-xml-base') => self::signed(
                self::replace(self::RECIPIENT, 'xml:base="https://sp.example.com/saml/" Recipient="acs"', $base),
                ['_assertion'],
            ),
            self::refused('response-relative-audience-under-an-xml-base') => self::signed(
                self::replace(
                    self::AUDIENCE,
                    '<saml:Audience xml:base="https://sp.example.com/">saml</saml:Audience>',
                    $base,
                ),
                ['_assertion'],
            ),
            self::refused('response-relative-issuer-under-an-xml-base') => self::signed(
                self::replace(
                    self::ASSERTION_ISSUER_IN_RESPONSE,
                    "\n    <saml:Issuer xml:base=\"https://idp.example.com/\">saml</saml:Issuer>",
                    $base,
                ),
                ['_assertion'],
            ),
            self::accepted('authn-request-xml-base-and-lang-on-every-element') => self::unsigned(
                self::onEveryStartTag(self::authnRequest(), self::XML_ATTRIBUTES),
            ),
            self::refused('authn-request-relative-assertion-consumer-service-url-under-an-xml-base') => self::unsigned(
                self::replace(
                    self::ACS,
                    'xml:base="https://sp.example.com/saml/" AssertionConsumerServiceURL="acs"',
                    self::authnRequest(),
                ),
            ),
            self::accepted('logout-request-xml-base-and-lang-on-every-element') => self::unsigned(
                self::onEveryStartTag(self::logoutRequest(), self::XML_ATTRIBUTES),
            ),
            self::accepted('logout-response-xml-base-and-lang-on-every-element') => self::unsigned(
                self::onEveryStartTag(self::logoutResponse(), self::XML_ATTRIBUTES),
            ),
            self::accepted('metadata-xml-base-and-lang-on-every-element') => self::unsigned(
                self::onEveryStartTag(self::identityProviderMetadata(), self::XML_ATTRIBUTES),
            ),
            self::refused('metadata-relative-location-under-an-xml-base') => self::unsigned(self::replace(
                'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso"',
                'Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" xml:base="https://idp.example.com/saml/" Location="sso"',
                self::identityProviderMetadata(),
            )),
        ];
    }

    /**
     * Section 3 rows 1, 7, 8 and 14, M-10, M-11, M-14: IDs that collide only after a normalisation the model must not
     * do, case, Unicode composition, a full-width character, whitespace, and xml:id, which is no ID attribute here.
     *
     * @return array<string, string>
     */
    private static function identifiers(): array
    {
        $precomposed = "_assertion\u{E9}";
        $decomposed = "_assertione\u{301}";
        $composed = self::replace('ID="_assertion"', sprintf('ID="%s"', $precomposed), self::response());
        $signed = self::signed(self::response(), ['_assertion']);
        $signedComposed = self::signed($composed, [$precomposed]);
        $original = self::element($signed, 'saml:Assertion');

        return [
            self::refused('response-wrapped-id-in-another-case') => self::unsigned(
                self::wrappedWithId('_ASSERTION', $original, $signed),
            ),
            self::refused('response-wrapped-id-in-another-unicode-composition') => self::unsigned(self::wrappedWithId(
                $decomposed,
                self::element($signedComposed, 'saml:Assertion'),
                $signedComposed,
            )),
            self::refused('response-wrapped-id-with-a-full-width-low-line') => self::unsigned(
                self::wrappedWithId("\u{FF3F}assertion", $original, $signed),
            ),
            self::refused('response-wrapped-id-with-a-trailing-space') => self::declared(
                self::wrappedWithId('_assertion ', $original, $signed),
            ),
            self::refused('response-wrapped-id-as-an-xml-id') => self::unsigned(self::inExtensions(
                self::replace(
                    $original,
                    self::replace(
                        'ID="_evil"',
                        'ID="_evil" xml:id="_assertion"',
                        self::withSignatureOf(self::evil(), $original),
                    ),
                    $signed,
                ),
                $original,
            )),
            self::refused('response-in-response-to-in-another-case') => self::answering('_REQUEST'),
            self::refused('response-in-response-to-in-another-unicode-composition') => self::answering("_requeste\u{301}"),
            self::accepted('response-in-response-to-precomposed') => self::answering("_request\u{E9}"),
            self::refused('response-in-response-to-with-a-trailing-space') => self::answering('_request '),
            self::accepted('response-assertion-id-in-another-case') => self::signed(
                self::replace('ID="_assertion"', 'ID="_ASSERTION"', self::response()),
                ['_ASSERTION'],
            ),
            self::accepted('response-assertion-id-precomposed') => $signedComposed,
            self::accepted('response-assertion-id-decomposed') => self::signed(
                self::replace('ID="_assertion"', sprintf('ID="%s"', $decomposed), self::response()),
                [$decomposed],
            ),
            self::refused('response-id-equal-to-the-assertion-id') => self::declared(
                self::replace('ID="_response"', 'ID="_assertion"', $signed),
            ),
            self::accepted('response-id-equal-to-the-assertion-id-in-another-case') => self::signed(
                self::replace('ID="_response"', 'ID="_Assertion"', self::response()),
                ['_assertion'],
            ),
            self::refused('logout-response-in-response-to-in-another-case') => self::unsigned(self::replace(
                'InResponseTo="_logout-request"',
                'InResponseTo="_LOGOUT-REQUEST"',
                self::logoutResponse(),
            )),
        ];
    }

    /**
     * M-6, M-7: times at the edges of their lexical form, the IssueInstant of an unsigned AuthnRequest and the
     * validUntil of metadata carrying them; nine fractional digits, and the tenth; a bound missed by less than the
     * microsecond the times are compared to.
     *
     * @return array<string, string>
     */
    private static function times(): array
    {
        return [
            self::accepted('authn-request-issue-instant-with-nine-fractional-digits') => self::issuedAt('2026-09-30T11:59:59.123456789Z'),
            self::refused('authn-request-issue-instant-with-ten-fractional-digits') => self::issuedAt('2026-09-30T11:59:59.1234567891Z'),
            self::refused('authn-request-issue-instant-with-a-dot-and-no-digit') => self::issuedAt('2026-09-30T11:59:59.Z'),
            self::refused('authn-request-issue-instant-with-a-lower-case-z') => self::issuedAt('2026-09-30T11:59:59z'),
            self::refused('authn-request-issue-instant-with-a-lower-case-t') => self::issuedAt('2026-09-30t11:59:59Z'),
            self::refused('authn-request-issue-instant-with-a-space-for-the-t') => self::issuedAt('2026-09-30 11:59:59Z'),
            self::refused('authn-request-issue-instant-with-a-plus-sign') => self::issuedAt('+2026-09-30T11:59:59Z'),
            self::refused('authn-request-issue-instant-with-a-five-digit-year') => self::issuedAt('02026-09-30T11:59:59Z'),
            self::refused('authn-request-issue-instant-with-a-negative-year') => self::issuedAt('-2026-09-30T11:59:59Z'),
            self::refused('authn-request-issue-instant-with-minus-zero') => self::issuedAt('2026-09-30T11:59:59-00:00'),
            self::refused('authn-request-issue-instant-with-z-and-an-offset') => self::issuedAt('2026-09-30T11:59:59Z+00:00'),
            self::refused('authn-request-issue-instant-in-full-width-digits') => self::issuedAt("\u{FF12}\u{FF10}\u{FF12}\u{FF16}-09-30T11:59:59Z"),
            self::refused('authn-request-issue-instant-in-arabic-indic-digits') => self::issuedAt("\u{662}\u{660}\u{662}\u{666}-09-30T11:59:59Z"),
            self::refused('authn-request-issue-instant-with-a-one-digit-month') => self::issuedAt('2026-9-30T11:59:59Z'),
            self::refused('authn-request-issue-instant-without-seconds') => self::issuedAt('2026-09-30T11:59Z'),
            self::refused('authn-request-issue-instant-with-a-tab-character-reference') => self::issuedAtAsWritten('2026-09-30T11:59:59Z&#9;'),
            self::accepted('authn-request-issue-instant-100-nanoseconds-after-now-plus-the-skew') => self::issuedAt('2026-09-30T12:03:00.0000001Z'),
            self::refused('authn-request-issue-instant-a-microsecond-after-now-plus-the-skew') => self::issuedAt('2026-09-30T12:03:00.000001Z'),
            self::accepted('response-not-before-100-nanoseconds-after-now-plus-the-skew') => self::signed(
                self::replace(
                    'NotBefore="2026-09-30T11:59:28Z"',
                    'NotBefore="2026-09-30T12:03:00.0000001Z"',
                    self::response(),
                ),
                ['_assertion'],
            ),
            self::accepted('metadata-valid-until-on-a-leap-day') => self::validUntil('2028-02-29T00:00:00Z'),
            self::refused('metadata-valid-until-on-29-february-2100') => self::validUntil('2100-02-29T00:00:00Z'),
            self::refused('metadata-valid-until-on-29-february-2027') => self::validUntil('2027-02-29T00:00:00Z'),
            self::refused('metadata-valid-until-on-31-april') => self::validUntil('2027-04-31T00:00:00Z'),
            self::accepted('metadata-valid-until-at-the-end-of-year-9999') => self::validUntil('9999-12-31T23:59:59.999999999Z'),
            self::refused('metadata-valid-until-in-year-0000') => self::validUntil('0000-01-01T00:00:00Z'),
        ];
    }

    /**
     * M-6: booleans at the edges of their four lexical forms, compared as strings and never cast.
     *
     * @return array<string, string>
     */
    private static function booleans(): array
    {
        return [
            self::accepted('authn-request-is-passive-1') => self::passive('1'),
            self::accepted('authn-request-force-authn-0') => self::unsigned(self::replace(
                'ProtocolBinding=',
                'ForceAuthn="0" ProtocolBinding=',
                self::authnRequest(),
            )),
            self::refused('authn-request-is-passive-capitalised') => self::passive('True'),
            self::refused('authn-request-is-passive-in-upper-case') => self::passive('FALSE'),
            self::refused('authn-request-is-passive-01') => self::passive('01'),
            self::refused('authn-request-is-passive-plus-1') => self::passive('+1'),
            self::refused('authn-request-is-passive-1.0') => self::passive('1.0'),
            self::refused('authn-request-is-passive-empty') => self::passive(''),
            self::refused('authn-request-is-passive-yes') => self::passive('yes'),
            self::refused('authn-request-is-passive-in-full-width-letters') => self::passive("\u{FF54}\u{FF52}\u{FF55}\u{FF45}"),
            self::refused('authn-request-is-passive-with-a-zero-width-space') => self::passive("true\u{200B}"),
            self::refused('authn-request-is-passive-with-a-tab-character-reference') => self::passive('true&#9;'),
            self::refused('authn-request-allow-create-on') => self::unsigned(self::replace(
                'AllowCreate="true"',
                'AllowCreate="on"',
                self::authnRequest(),
            )),
            self::accepted('metadata-want-authn-requests-signed-1') => self::unsigned(self::replace(
                'WantAuthnRequestsSigned="true"',
                'WantAuthnRequestsSigned="1"',
                self::identityProviderMetadata(),
            )),
            self::refused('metadata-is-default-in-upper-case') => self::unsigned(self::replace(
                'isDefault="true"',
                'isDefault="TRUE"',
                self::serviceProviderMetadata(),
            )),
        ];
    }

    /**
     * Section 3 rows 5, 6 and 10, M-8, M-9: URIs that differ from the expected one by what a normaliser would erase,
     * each compared exactly.
     *
     * @return array<string, string>
     */
    private static function uris(): array
    {
        return [
            self::refused('response-destination-scheme-in-upper-case') => self::withDestination('HTTPS://sp.example.com/saml/acs'),
            self::refused('response-destination-with-the-default-port') => self::withDestination('https://sp.example.com:443/saml/acs'),
            self::refused('response-destination-with-an-empty-port') => self::withDestination('https://sp.example.com:/saml/acs'),
            self::refused('response-destination-host-with-a-trailing-dot') => self::withDestination('https://sp.example.com./saml/acs'),
            self::refused('response-destination-with-a-dot-segment') => self::withDestination('https://sp.example.com/saml/./acs'),
            self::refused('response-destination-with-a-dot-dot-segment') => self::withDestination('https://sp.example.com/saml/x/../acs'),
            self::refused('response-destination-with-a-percent-encoded-slash') => self::withDestination('https://sp.example.com/saml%2Facs'),
            self::refused('response-destination-with-user-information') => self::withDestination('https://sp.example.com@attacker.example.com/saml/acs'),
            self::refused('response-destination-with-an-empty-query') => self::withDestination('https://sp.example.com/saml/acs?'),
            self::refused('response-destination-with-an-empty-fragment') => self::withDestination('https://sp.example.com/saml/acs#'),
            self::refused('response-destination-with-a-homograph-host') => self::withDestination("https://sp.ex\u{430}mple.com/saml/acs"),
            self::refused('response-destination-with-a-zero-width-space') => self::withDestination("https://sp.example.com/saml/acs\u{200B}"),
            self::refused('response-recipient-scheme-in-upper-case') => self::withRecipient('HTTPS://sp.example.com/saml/acs'),
            self::refused('response-recipient-with-the-default-port') => self::withRecipient('https://sp.example.com:443/saml/acs'),
            self::refused('response-recipient-with-a-dot-segment') => self::withRecipient('https://sp.example.com/saml/./acs'),
            self::refused('response-audience-scheme-in-upper-case') => self::withAudience('HTTPS://sp.example.com/saml'),
            self::refused('response-audience-with-a-trailing-slash') => self::withAudience('https://sp.example.com/saml/'),
            self::refused('response-audience-host-with-a-trailing-dot') => self::withAudience('https://sp.example.com./saml'),
            self::refused('response-assertion-issuer-host-in-upper-case') => self::withIssuer('https://IDP.example.com/saml'),
            self::refused('response-assertion-issuer-with-a-trailing-slash') => self::withIssuer('https://idp.example.com/saml/'),
            self::refused('authn-request-assertion-consumer-service-url-scheme-in-upper-case') => self::withAssertionConsumerServiceUrl('HTTPS://sp.example.com/saml/acs'),
            self::refused('authn-request-assertion-consumer-service-url-host-in-upper-case') => self::withAssertionConsumerServiceUrl('https://SP.example.com/saml/acs'),
            self::refused('authn-request-assertion-consumer-service-url-with-the-default-port') => self::withAssertionConsumerServiceUrl('https://sp.example.com:443/saml/acs'),
            self::refused('authn-request-assertion-consumer-service-url-with-a-trailing-slash') => self::withAssertionConsumerServiceUrl('https://sp.example.com/saml/acs/'),
            self::refused('authn-request-assertion-consumer-service-url-with-a-dot-segment') => self::withAssertionConsumerServiceUrl('https://sp.example.com/saml/./acs'),
            self::refused('authn-request-assertion-consumer-service-url-percent-encoded') => self::withAssertionConsumerServiceUrl('https://sp.example.com/saml/%61cs'),
            self::refused('authn-request-destination-with-the-default-port') => self::unsigned(self::replace(
                'Destination="https://idp.example.com/saml/sso"',
                'Destination="https://idp.example.com:443/saml/sso"',
                self::authnRequest(),
            )),
            self::refused('authn-request-issuer-with-a-trailing-slash') => self::unsigned(self::replace(
                '<saml:Issuer>https://sp.example.com/saml</saml:Issuer>',
                '<saml:Issuer>https://sp.example.com/saml/</saml:Issuer>',
                self::authnRequest(),
            )),
            self::refused('logout-request-destination-with-a-trailing-slash') => self::unsigned(self::replace(
                'Destination="https://sp.example.com/saml/slo"',
                'Destination="https://sp.example.com/saml/slo/"',
                self::logoutRequest(),
            )),
            self::refused('logout-response-destination-host-in-upper-case') => self::unsigned(self::replace(
                'Destination="https://idp.example.com/saml/slo"',
                'Destination="https://IDP.example.com/saml/slo"',
                self::logoutResponse(),
            )),
        ];
    }

    /**
     * Section 3 row 16, section 7, M-17: every bound at its value and one over, the lengths of M-6 and M-12 among
     * them, in characters of one byte and of two.
     *
     * @return array<string, string>
     */
    private static function bounds(): array
    {
        $idp = self::identityProviderMetadata();
        $signing = self::element($idp, 'md:KeyDescriptor');
        $single = 'https://idp.example.com/saml/sso';

        return [
            self::accepted('response-audience-of-1024-characters') => self::withSecondAudience(
                'https://' . str_repeat('a', 1016),
            ),
            self::refused('response-audience-of-1025-characters') => self::withSecondAudience(
                'https://' . str_repeat('a', 1017),
            ),
            self::accepted('response-audience-of-1024-two-byte-characters') => self::withSecondAudience(
                'https://' . str_repeat("\u{E9}", 1016),
            ),
            self::refused('response-audience-of-1025-two-byte-characters') => self::withSecondAudience(
                'https://' . str_repeat("\u{E9}", 1017),
            ),
            self::accepted('response-persistent-name-id-of-256-characters') => self::withNameId('SAML:2.0:nameid-format:persistent', str_repeat(
                'a',
                256,
            )),
            self::accepted('response-persistent-name-id-of-256-two-byte-characters') => self::withNameId('SAML:2.0:nameid-format:persistent', str_repeat(
                "\u{E9}",
                256,
            )),
            self::refused('response-persistent-name-id-of-257-two-byte-characters') => self::withNameId('SAML:2.0:nameid-format:persistent', str_repeat(
                "\u{E9}",
                257,
            )),
            self::accepted('response-transient-name-id-of-256-characters') => self::withNameId('SAML:2.0:nameid-format:transient', str_repeat(
                'a',
                256,
            )),
            self::refused('response-transient-name-id-of-257-characters') => self::withNameId('SAML:2.0:nameid-format:transient', str_repeat(
                'a',
                257,
            )),
            self::accepted('response-unspecified-name-id-of-1024-characters') => self::withNameId('SAML:1.1:nameid-format:unspecified', str_repeat(
                'a',
                1024,
            )),
            self::refused('response-unspecified-name-id-of-1025-characters') => self::withNameId('SAML:1.1:nameid-format:unspecified', str_repeat(
                'a',
                1025,
            )),
            self::accepted('response-assertion-id-of-128-bytes') => self::withAssertionId('_' . str_repeat('a', 127)),
            self::refused('response-assertion-id-of-129-bytes') => self::declared(self::replace(
                'ID="_assertion"',
                sprintf('ID="_%s"', str_repeat('a', 128)),
                self::response(),
            )),
            self::accepted('response-assertion-id-of-128-bytes-in-two-byte-characters') => self::withAssertionId(
                '_' . str_repeat("\u{E9}", 63) . 'a',
            ),
            self::accepted('response-in-response-to-of-128-bytes') => self::answering('_' . str_repeat('r', 127)),
            self::refused('response-in-response-to-of-129-bytes') => self::answering('_' . str_repeat('r', 128)),
            self::accepted('response-issued-exactly-max-message-age-ago') => self::signed(
                self::replace(
                    'ID="_response" Version="2.0" IssueInstant="2026-09-30T11:59:59Z"',
                    'ID="_response" Version="2.0" IssueInstant="2026-09-30T11:55:00Z"',
                    self::response(),
                ),
                ['_assertion'],
            ),
            self::accepted('authn-request-sixteen-class-references') => self::withClassReferences(16),
            self::refused('authn-request-seventeen-class-references') => self::withClassReferences(17),
            self::accepted('logout-request-sixteen-session-indexes') => self::repeated(
                '<samlp:SessionIndex>_session</samlp:SessionIndex>',
                '<samlp:SessionIndex>_session</samlp:SessionIndex>',
                16,
                self::logoutRequest(),
            ),
            self::accepted('metadata-sixteen-signing-certificates') => self::repeated($signing, $signing, 16, $idp),
            self::accepted('metadata-sixteen-encryption-certificates') => self::repeated(
                $signing,
                $signing . str_repeat(self::replace('use="signing"', 'use="encryption"', $signing), 16),
                1,
                $idp,
            ),
            self::accepted('metadata-sixty-four-single-sign-on-services') => self::repeated(
                sprintf(
                    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>',
                    $single,
                ),
                sprintf(
                    '<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="%s"/>',
                    $single,
                ),
                63,
                $idp,
            ),
            self::accepted('metadata-sixty-four-single-logout-services') => self::repeated(
                '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/slo"/>',
                '<md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/slo"/>',
                64,
                $idp,
            ),
            self::accepted('metadata-sixty-four-assertion-consumer-services') => self::unsigned(self::replace(
                '</md:SPSSODescriptor>',
                implode('', array_map(
                    static fn (int $index): string => sprintf(
                        '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/acs/%1$d" index="%1$d"/>',
                        $index,
                    ),
                    [...self::range(1, 63)],
                ))
                    . '</md:SPSSODescriptor>',
                self::serviceProviderMetadata(),
            )),
            self::accepted('metadata-sixteen-name-id-formats') => self::repeated(
                '<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>',
                '<md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>',
                16,
                $idp,
            ),
            self::accepted('metadata-entity-id-of-1024-characters') => self::unsigned(self::replace(
                'entityID="https://idp.example.com/saml"',
                sprintf('entityID="https://%s"', str_repeat('a', 1016)),
                $idp,
            )),
        ];
    }

    /**
     * Section 3 row 4, M-12, I-12: comments inserted into the signed elements after signing, which the exclusive
     * canonical form without comments leaves out of the digest, and processing instructions, which it renders; both
     * before signing; a CDATA section and a character reference.
     *
     * @return array<string, string>
     */
    private static function commentsAndInstructions(): array
    {
        $signed = self::signed(self::response(), ['_assertion']);
        $original = self::element($signed, 'saml:Assertion');
        $both = self::signed(self::response(), ['_assertion', '_response']);
        $signature = self::element($original, 'ds:Signature');
        $withoutSignature = self::replace($signature, "\u{0}", $original);
        $signedRequest = self::signed(self::authnRequest(), ['_authn-request'], 'sp');
        $signedLogout = self::signed(self::logoutRequest(), ['_logout-request']);

        return [
            self::accepted('response-comments-inserted-after-signing') => self::declared(
                self::replace($original, self::everywhere($original, '<!--c-->'), $signed),
            ),
            self::accepted('response-signed-both-comments-inserted-after-signing') => self::declared(
                self::everywhere($both, '<!--c-->'),
            ),
            self::refused('response-processing-instructions-inserted-after-signing') => self::declared(self::replace(
                $original,
                self::replace("\u{0}", $signature, self::everywhere($withoutSignature, '<?c?>')),
                $signed,
            )),
            self::refused('response-processing-instruction-in-signed-info-after-signing') => self::declared(self::replace(
                '<ds:SignedInfo>',
                '<ds:SignedInfo><?c?>',
                $signed,
            )),
            self::refused('response-processing-instruction-in-the-status-of-a-signed-response') => self::declared(
                self::replace(self::SUCCESS, self::SUCCESS . '<?c?>', $both),
            ),
            self::accepted('response-comments-and-processing-instructions-before-signing') => self::signed(
                self::everywhere(self::element(self::response(), 'saml:Assertion'), '<!--c--><?c?>', self::response()),
                ['_assertion'],
            ),
            self::accepted('response-name-id-in-a-cdata-section') => self::signed(
                self::replace('>_7a2f4c1d9e<', '><![CDATA[_7a2f4c1d9e]]><', self::response()),
                ['_assertion'],
            ),
            self::refused('response-name-id-behind-a-space-character-reference') => self::signed(
                self::replace('>_7a2f4c1d9e<', '>&#x20;_7a2f4c1d9e<', self::response()),
                ['_assertion'],
            ),
            self::accepted('authn-request-comments-inserted-after-signing') => self::declared(
                self::everywhere($signedRequest, '<!--c-->'),
            ),
            self::refused('authn-request-processing-instruction-after-signing') => self::declared(
                self::replace('<saml:Issuer>', '<?c?><saml:Issuer>', $signedRequest),
            ),
            self::accepted('logout-request-comments-inserted-after-signing') => self::declared(
                self::everywhere($signedLogout, '<!--c-->'),
            ),
            self::accepted('metadata-certificate-split-by-a-comment-and-a-processing-instruction') => self::declared(
                preg_replace(
                    '~(<ds:X509Certificate>[A-Za-z0-9+/]{40})([A-Za-z0-9+/]{40})~',
                    '$1<!--c-->$2<?c?>',
                    self::identityProviderMetadata(),
                    1,
                ) ?? throw new LogicException('The certificate could not be split.'),
            ),
            self::accepted('metadata-comments-and-processing-instructions-everywhere') => self::declared(
                self::everywhere(self::identityProviderMetadata(), '<!--c--><?c?>'),
            ),
        ];
    }

    /**
     * The rows of section 3 the groups above do not reach: key substitution, a signature out of its place, a condition
     * of another namespace, the vocabularies of metadata in another case.
     *
     * @return array<string, string>
     */
    private static function otherRows(): array
    {
        $responseOnly = self::signed(self::response(), ['_response']);
        $responseSignature = self::element($responseOnly, 'ds:Signature');
        $signed = self::signed(self::response(), ['_assertion']);

        return [
            self::refused('response-assertion-signed-by-another-key-with-the-identity-provider-certificate') => self::signed(
                self::response(),
                ['_assertion'],
                'sp',
                self::file('keys/idp-signing-certificate.pem'),
            ),
            self::refused('response-signature-moved-into-the-extensions') => self::unsigned(self::replace(
                self::STATUS,
                "\n  <samlp:Extensions>" . $responseSignature . '</samlp:Extensions>' . self::STATUS,
                self::replace(self::RESPONSE_ISSUER . $responseSignature, self::RESPONSE_ISSUER, $responseOnly),
            )),
            self::accepted('response-failing-signature-in-the-extensions') => self::unsigned(self::replace(
                self::STATUS,
                "\n  <samlp:Extensions>"
                . self::replace(
                    self::text($responseSignature, 'ds:DigestValue'),
                    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=',
                    $responseSignature,
                )
                . '</samlp:Extensions>'
                . self::STATUS,
                $signed,
            )),
            self::refused('response-condition-in-another-namespace') => self::signed(
                self::replace(
                    "\n    </saml:Conditions>",
                    '<x:Condition xmlns:x="urn:example:conditions"/>' . "\n    </saml:Conditions>",
                    self::response(),
                ),
                ['_assertion'],
            ),
            self::refused('response-same-signed-assertion-in-another-response') => self::unsigned(self::replace(
                'ID="_response" Version="2.0" IssueInstant="2026-09-30T11:59:59Z"',
                'ID="_another-response" Version="2.0" IssueInstant="2026-09-30T11:59:59.5Z"',
                $signed,
            )),
            self::refused('response-assertion-issued-a-year-ago-within-its-bearer-window') => self::signed(
                self::replace(
                    'ID="_assertion" Version="2.0" IssueInstant="2026-09-30T11:59:58Z"',
                    'ID="_assertion" Version="2.0" IssueInstant="2025-09-30T11:59:58Z"',
                    self::response(),
                ),
                ['_assertion'],
            ),
            self::refused('response-empty-audience-next-to-ours') => self::signed(
                self::replace(self::AUDIENCE, self::AUDIENCE . '<saml:Audience/>', self::response()),
                ['_assertion'],
            ),
            self::refused('response-name-id-with-a-right-to-left-override') => self::signed(
                self::replace('>_7a2f4c1d9e<', ">_7a2f\u{202E}4c1d9e<", self::response()),
                ['_assertion'],
            ),
            self::refused('response-status-code-success-in-lower-case') => self::unsigned(self::replace(
                'status:Success',
                'status:success',
                $signed,
            )),
            self::refused('response-confirmation-method-bearer-capitalised') => self::signed(
                self::replace('cm:bearer', 'cm:Bearer', self::response()),
                ['_assertion'],
            ),
            self::refused('response-name-id-format-in-another-case') => self::signed(
                self::replace('nameid-format:persistent', 'nameid-format:Persistent', self::response()),
                ['_assertion'],
            ),
            self::refused('response-version-2.00') => self::signed(
                self::replace('ID="_response" Version="2.0"', 'ID="_response" Version="2.00"', self::response()),
                ['_assertion'],
            ),
            self::refused('logout-request-signed-name-id-moved-into-the-extensions') => self::declared(self::replace(
                self::NAME_ID,
                str_replace('>_7a2f4c1d9e<', '>_attacker<', self::NAME_ID),
                self::replace(
                    '</ds:Signature>',
                    '</ds:Signature><samlp:Extensions>' . self::NAME_ID . '</samlp:Extensions>',
                    self::signed(self::logoutRequest(), ['_logout-request']),
                ),
                2,
            )),
            self::refused('metadata-key-descriptor-use-with-a-trailing-space') => self::unsigned(self::replace(
                'use="signing"',
                'use="signing "',
                self::identityProviderMetadata(),
            )),
            self::refused('metadata-key-descriptor-use-capitalised') => self::unsigned(self::replace(
                'use="signing"',
                'use="Signing"',
                self::identityProviderMetadata(),
            )),
            self::refused('metadata-protocol-support-enumeration-in-upper-case') => self::unsigned(self::replace(
                'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"',
                'protocolSupportEnumeration="URN:OASIS:NAMES:TC:SAML:2.0:PROTOCOL"',
                self::identityProviderMetadata(),
            )),
            self::refused('metadata-bindings-in-another-case') => self::unsigned(str_replace(
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-',
                'urn:oasis:names:tc:SAML:2.0:bindings:http-',
                self::identityProviderMetadata(),
            )),
        ];
    }

    /**
     * $response with the signed assertion $original moved into its samlp:Extensions, and in its place the attacker's assertion of ID $id carrying the signature of $original.
     */
    private static function wrappedWithId(string $id, string $original, string $response): string
    {
        return self::inExtensions(
            self::replace($original, self::withSignatureOf(self::evil($id), $original), $response),
            $original,
        );
    }

    /**
     * The valid response and its assertion answering the request $id, both signed.
     */
    private static function answering(string $id): string
    {
        return self::signed(
            str_replace('InResponseTo="_request"', sprintf('InResponseTo="%s"', $id), self::response()),
            ['_assertion', '_response'],
        );
    }

    /**
     * The unsigned AuthnRequest issued at $time, as the serializer writes it.
     */
    private static function issuedAt(string $time): string
    {
        return self::unsigned(self::replace(
            'IssueInstant="2026-09-30T11:59:59Z"',
            sprintf('IssueInstant="%s"', $time),
            self::authnRequest(),
        ));
    }

    /**
     * The unsigned AuthnRequest issued at $time, its bytes as written here.
     */
    private static function issuedAtAsWritten(string $time): string
    {
        return self::declared(self::replace(
            'IssueInstant="2026-09-30T11:59:59Z"',
            sprintf('IssueInstant="%s"', $time),
            self::authnRequest(),
        ));
    }

    /**
     * The metadata of the identity provider valid until $time.
     */
    private static function validUntil(string $time): string
    {
        return self::unsigned(self::replace(
            'entityID="https://idp.example.com/saml"',
            sprintf('entityID="https://idp.example.com/saml" validUntil="%s"', $time),
            self::identityProviderMetadata(),
        ));
    }

    /**
     * The unsigned AuthnRequest with IsPassive $value, its bytes as written here.
     */
    private static function passive(string $value): string
    {
        return self::declared(self::replace(
            'ProtocolBinding=',
            sprintf('IsPassive="%s" ProtocolBinding=', $value),
            self::authnRequest(),
        ));
    }

    /**
     * The valid response to the Destination $url, the assertion and the response signed.
     */
    private static function withDestination(string $url): string
    {
        return self::signed(
            self::replace(self::DESTINATION, sprintf('Destination="%s"', $url), self::response()),
            ['_assertion', '_response'],
        );
    }

    /**
     * The valid response whose bearer confirmation names the Recipient $url, the assertion signed.
     */
    private static function withRecipient(string $url): string
    {
        return self::signed(
            self::replace(self::RECIPIENT, sprintf('Recipient="%s"', $url), self::response()),
            ['_assertion'],
        );
    }

    /**
     * The valid response whose one Audience is $url, the assertion signed.
     */
    private static function withAudience(string $url): string
    {
        return self::signed(
            self::replace(self::AUDIENCE, sprintf('<saml:Audience>%s</saml:Audience>', $url), self::response()),
            ['_assertion'],
        );
    }

    /**
     * The valid response whose assertion names the Issuer $url, the assertion signed.
     */
    private static function withIssuer(string $url): string
    {
        return self::signed(
            self::replace(
                self::ASSERTION_ISSUER_IN_RESPONSE,
                sprintf("\n    <saml:Issuer>%s</saml:Issuer>", $url),
                self::response(),
            ),
            ['_assertion'],
        );
    }

    /**
     * The unsigned AuthnRequest whose AssertionConsumerServiceURL is $url.
     */
    private static function withAssertionConsumerServiceUrl(string $url): string
    {
        return self::unsigned(
            self::replace(self::ACS, sprintf('AssertionConsumerServiceURL="%s"', $url), self::authnRequest()),
        );
    }

    /**
     * The valid response with $audience after our Audience, the assertion signed.
     */
    private static function withSecondAudience(string $audience): string
    {
        return self::signed(
            self::replace(
                self::AUDIENCE,
                sprintf('%s<saml:Audience>%s</saml:Audience>', self::AUDIENCE, $audience),
                self::response(),
            ),
            ['_assertion'],
        );
    }

    /**
     * The valid response whose NameID is $value of the format urn:oasis:names:tc:$format, the assertion signed.
     */
    private static function withNameId(string $format, string $value): string
    {
        return self::signed(
            self::replace(
                self::NAME_ID,
                sprintf('<saml:NameID Format="urn:oasis:names:tc:%s">%s</saml:NameID>', $format, $value),
                self::response(),
            ),
            ['_assertion'],
        );
    }

    /**
     * The valid response whose assertion has the ID $id, the assertion signed.
     */
    private static function withAssertionId(string $id): string
    {
        return self::signed(
            self::replace('ID="_assertion"', sprintf('ID="%s"', $id), self::response()),
            [$id],
        );
    }

    /**
     * The unsigned AuthnRequest asking for $count class references.
     */
    private static function withClassReferences(int $count): string
    {
        return self::unsigned(self::replace(
            '</samlp:AuthnRequest>',
            '<samlp:RequestedAuthnContext>'
            . str_repeat(
                '<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:X509</saml:AuthnContextClassRef>',
                $count,
            )
            . '</samlp:RequestedAuthnContext></samlp:AuthnRequest>',
            self::authnRequest(),
        ));
    }

    /**
     * $xml with $search replaced by $count times $repeated, unsigned.
     */
    private static function repeated(string $search, string $repeated, int $count, string $xml): string
    {
        return self::unsigned(
            self::replace($search, str_repeat($repeated, $count), $xml),
        );
    }

    /**
     * The valid response, unsigned: one assertion of a persistent NameID, a bearer confirmation, one audience, an
     * authentication statement and one attribute, as story #7's builder writes it.
     */
    private static function response(): string
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
     * The valid AuthnRequest of the service provider, unsigned, its assertion consumer service named by URL.
     */
    private static function authnRequest(): string
    {
        return <<<'XML'
            <samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_authn-request" Version="2.0" IssueInstant="2026-09-30T11:59:59Z" Destination="https://idp.example.com/saml/sso" AssertionConsumerServiceURL="https://sp.example.com/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
              <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
              <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
            </samlp:AuthnRequest>
            XML;
    }

    /**
     * The valid LogoutRequest of the identity provider to the service provider, unsigned.
     */
    private static function logoutRequest(): string
    {
        return <<<'XML'
            <samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout-request" Version="2.0" IssueInstant="2026-09-30T11:59:59Z" Destination="https://sp.example.com/saml/slo" NotOnOrAfter="2026-09-30T12:04:59Z" Reason="urn:oasis:names:tc:SAML:2.0:logout:user">
              <saml:Issuer>https://idp.example.com/saml</saml:Issuer>
              <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">_7a2f4c1d9e</saml:NameID>
              <samlp:SessionIndex>_session</samlp:SessionIndex>
            </samlp:LogoutRequest>
            XML;
    }

    /**
     * The valid LogoutResponse of the service provider to the identity provider, unsigned.
     */
    private static function logoutResponse(): string
    {
        return <<<'XML'
            <samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_logout-response" Version="2.0" IssueInstant="2026-09-30T11:59:59Z" Destination="https://idp.example.com/saml/slo" InResponseTo="_logout-request">
              <saml:Issuer>https://sp.example.com/saml</saml:Issuer>
              <samlp:Status>
                <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
              </samlp:Status>
            </samlp:LogoutResponse>
            XML;
    }

    /**
     * The metadata of the identity provider, its signing key the test key of its role.
     */
    private static function identityProviderMetadata(): string
    {
        return sprintf(
            <<<'XML'
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com/saml">
                  <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" WantAuthnRequestsSigned="true">
                    <md:KeyDescriptor use="signing">
                      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:X509Data>
                          <ds:X509Certificate>%s</ds:X509Certificate>
                        </ds:X509Data>
                      </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/slo"/>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/saml/sso"/>
                    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/saml/sso"/>
                  </md:IDPSSODescriptor>
                </md:EntityDescriptor>
                XML,
            self::certificate('idp'),
        );
    }

    /**
     * The metadata of the service provider, its signing key the test key of its role, one assertion consumer service.
     */
    private static function serviceProviderMetadata(): string
    {
        return sprintf(
            <<<'XML'
                <md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com/saml">
                  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol" AuthnRequestsSigned="true" WantAssertionsSigned="true">
                    <md:KeyDescriptor use="signing">
                      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                        <ds:X509Data>
                          <ds:X509Certificate>%s</ds:X509Certificate>
                        </ds:X509Data>
                      </ds:KeyInfo>
                    </md:KeyDescriptor>
                    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/slo"/>
                    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:transient</md:NameIDFormat>
                    <md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.com/saml/acs" index="0" isDefault="true"/>
                  </md:SPSSODescriptor>
                </md:EntityDescriptor>
                XML,
            self::certificate('sp'),
        );
    }

    /**
     * The unsigned assertion of the attacker, of ID $id, its NameID _attacker.
     */
    private static function evil(string $id = '_evil'): string
    {
        return self::replace(
            '>_7a2f4c1d9e<',
            '>_attacker<',
            self::replace(
                'ID="_assertion"',
                sprintf('ID="%s"', $id),
                self::element(self::response(), 'saml:Assertion'),
            ),
        );
    }

    /**
     * $assertion carrying, after its Issuer, the ds:Signature of the signed assertion $original.
     */
    private static function withSignatureOf(string $assertion, string $original): string
    {
        return self::replace(
            self::ASSERTION_ISSUER,
            self::ASSERTION_ISSUER . self::element($original, 'ds:Signature'),
            $assertion,
        );
    }

    /**
     * $response with $wrapped in a samlp:StatusDetail after its StatusCode.
     */
    private static function inStatusDetail(string $response, string $wrapped): string
    {
        return self::replace(
            self::SUCCESS,
            self::SUCCESS . '<samlp:StatusDetail>' . $wrapped . '</samlp:StatusDetail>',
            $response,
        );
    }

    /**
     * $response with $wrapped in a samlp:Extensions before its Status.
     */
    private static function inExtensions(string $response, string $wrapped): string
    {
        return self::replace(
            self::STATUS,
            "\n  <samlp:Extensions>" . $wrapped . '</samlp:Extensions>' . self::STATUS,
            $response,
        );
    }

    /**
     * $xml with the element $qualifiedName, its first, renamed in its start tag to $start and in its end tag to $end.
     */
    private static function renamed(string $xml, string $qualifiedName, string $start, string $end): string
    {
        $element = self::element($xml, $qualifiedName);
        $renamed = preg_replace(
            [
                sprintf('~\A<%s~', preg_quote($qualifiedName, '~')),
                sprintf('~</%s>\z~', preg_quote($qualifiedName, '~')),
            ],
            ['<' . $start, '</' . $end . '>'],
            $element,
        ) ?? throw new LogicException('The element could not be renamed.');

        return self::replace($element, $renamed, $xml);
    }

    /**
     * $xml with $attributes added to every start tag, after the name of the element.
     */
    private static function onEveryStartTag(string $xml, string $attributes): string
    {
        return (
            preg_replace(
                '~<([A-Za-z_][\w.\-]*(?::[\w.\-]+)?)(?=[\s/>])~',
                '<$1' . $attributes,
                $xml,
            ) ?? throw new LogicException('The start tags could not be rewritten.')
        );
    }

    /**
     * $xml with $node before every child and every text of each element of $fragment, and inside every text that is
     * not whitespace alone, after its first character; $fragment is $xml unless it is a part of it.
     */
    private static function everywhere(string $fragment, string $node, ?string $xml = null): string
    {
        $inserted = preg_replace_callback(
            '~>([^<]*)<(?![?!])~u',
            static fn (array $match): string => trim($match[1]) === ''
                ? '>' . $node . $match[1] . '<'
                : '>' . $node . mb_substr($match[1], 0, 1) . $node . mb_substr($match[1], 1) . $node . '<',
            $fragment,
        ) ?? throw new LogicException('The nodes could not be inserted.');

        return $xml === null ? $inserted : self::replace($fragment, $inserted, $xml);
    }

    /**
     * The document, loaded then serialized as the serializer writes it, unsigned.
     */
    private static function unsigned(string $xml): string
    {
        return new Serializer()->serialize(SamlLoader::create()->load($xml));
    }

    /**
     * The bytes of a document the loader refuses, one whose signature a change after signing covers or not, or one
     * whose bytes the serializer would write otherwise, with the XML declaration the serializer writes in front.
     */
    private static function declared(string $xml): string
    {
        return preg_match('~\A<\?xml ~', $xml) === 1
            ? $xml
            : "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" . $xml . "\n";
    }

    /**
     * The document with an enveloped signature over each element of $ids, in order, after its saml:Issuer when it
     * has one and first otherwise (SAML Core §5.4.1).
     *
     * @param list<string> $ids
     * @param 'idp'|'sp' $key the test key of the identity provider, or of the service provider
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
     * The base64 of the certificate of a test key, on one line, as an X509Certificate carries it.
     *
     * @param 'idp'|'sp' $key
     */
    private static function certificate(string $key): string
    {
        return (
            preg_replace(
                '~-----[A-Z ]+-----|\s+~',
                '',
                self::file(sprintf('keys/%s-signing-certificate.pem', $key)),
            ) ?? throw new LogicException('The certificate could not be read.')
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

    /**
     * @return iterable<int>
     */
    private static function range(int $from, int $to): iterable
    {
        for ($value = $from; $value <= $to; ++$value) {
            yield $value;
        }
    }

    private static function refused(string $attempt): string
    {
        return sprintf('hostile/adversarial-%s-refused.xml', $attempt);
    }

    private static function accepted(string $attempt): string
    {
        return sprintf('behaviour/adversarial-%s-accepted.xml', $attempt);
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
