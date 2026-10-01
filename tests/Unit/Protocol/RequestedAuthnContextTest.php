<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Protocol;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Protocol\AuthnContextComparison;
use Beffroi\Saml2\Model\Protocol\RequestedAuthnContext;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3: the requested authentication context of an AuthnRequest, a comparison and its class references (SAML
 * Core §3.3.2.2.1).
 */
final class RequestedAuthnContextTest extends TestCase
{
    private const string PROTECTED_TRANSPORT = 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport';

    private const string X509 = 'urn:oasis:names:tc:SAML:2.0:ac:classes:X509';

    /**
     * Section 5.3: the comparison and the class references, in the order given.
     */
    #[Test]
    public function itHoldsItsComparisonAndClassReferences(): void
    {
        // When
        $context = new RequestedAuthnContext(AuthnContextComparison::Minimum, [self::X509, self::PROTECTED_TRANSPORT]);

        // Then
        static::assertSame(
            [AuthnContextComparison::Minimum, [self::X509, self::PROTECTED_TRANSPORT]],
            [$context->comparison, $context->authnContextClassRefs],
        );
    }

    /**
     * M-5, SAML Core §3.3.2.2.1: at least one class reference, whoever builds it.
     */
    #[Test]
    public function itRefusesNoClassReference(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A samlp:RequestedAuthnContext holds no saml:AuthnContextClassRef (M-5).');

        // When
        new RequestedAuthnContext(AuthnContextComparison::Exact, []);
    }

    /**
     * M-6: every class reference is a URI, the second as well as the first.
     */
    #[Test]
    public function itRefusesAClassReferenceThatIsNotAUri(): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A URI is not absolute (M-6).');

        // When
        new RequestedAuthnContext(AuthnContextComparison::Exact, [
            self::PROTECTED_TRANSPORT,
            'PasswordProtectedTransport',
        ]);
    }
}
