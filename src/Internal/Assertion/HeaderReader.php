<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Assertion;

use Beffroi\Saml2\Model\Assertion\Issuer;
use Beffroi\Saml2\Model\Exception\IssuerMismatch;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Value\Version;
use Beffroi\Xml\Core\Children;
use DateTimeImmutable;
use Dom\Element;

/**
 * The header of an assertion, section 6.1 step 7: Version 2.0, the ID, an IssueInstant not later than now plus the
 * skew (M-7), the Issuer of the identity provider (M-8); saml:Advice is refused by name (section 8), since what it
 * holds is covered by the signature of an assertion nobody reads.
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class HeaderReader
{
    /**
     * @return array{string, DateTimeImmutable, Issuer} the ID, the IssueInstant and the Issuer
     *
     * @throws MalformedMessage when an attribute is absent or not of its lexical form (M-6)
     * @throws OutsideValidityWindow when the IssueInstant is later than now plus the skew (M-7)
     * @throws IssuerMismatch when the Issuer is not the identity provider's (M-8)
     * @throws Unsupported when the assertion holds a saml:Advice (section 8)
     */
    public static function read(Element $assertion, AssertionContext $context): array
    {
        Version::read(Schema::attribute($assertion, 'saml:Assertion', 'Version'));
        $id = Schema::attribute($assertion, 'saml:Assertion', 'ID');
        $issueInstant = Time::read(Schema::attribute($assertion, 'saml:Assertion', 'IssueInstant'));
        if ($issueInstant > $context->latest()) {
            throw new OutsideValidityWindow('The IssueInstant of the assertion is later than now plus the clock skew (M-7).');
        }
        $issuer = IssuerReader::read(Children::one($assertion, Schema::saml('Issuer')), $context->identityProvider);
        Schema::unsupported(
            $assertion,
            [Schema::saml('Advice')],
            'The assertion holds a saml:Advice, which the package does not support (section 8).',
        );

        return [$id, $issueInstant, $issuer];
    }
}
