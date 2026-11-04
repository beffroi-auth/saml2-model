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
 * Section 6.1 step 7
 *
 * A saml:Advice is refused, since what it holds is covered by the signature of an assertion nobody reads.
 *
 * @internal
 */
final readonly class HeaderReader
{
    /**
     * @return array{string, DateTimeImmutable, Issuer} the ID, the IssueInstant and the Issuer
     *
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws IssuerMismatch
     * @throws Unsupported
     */
    public static function read(Element $assertion, AssertionContext $context): array
    {
        Version::read(Schema::attribute($assertion, 'saml:Assertion', 'Version'));
        $id = Schema::attribute($assertion, 'saml:Assertion', 'ID');
        $issueInstant = Time::read(Schema::attribute($assertion, 'saml:Assertion', 'IssueInstant'));
        if ($issueInstant > $context->window->latest()) {
            throw new OutsideValidityWindow('The IssueInstant of the assertion is later than now plus the clock skew (M-7).');
        }
        if ($issueInstant < $context->window->oldest()) {
            throw new OutsideValidityWindow('The IssueInstant of the assertion is older than maxMessageAge (M-7).');
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
