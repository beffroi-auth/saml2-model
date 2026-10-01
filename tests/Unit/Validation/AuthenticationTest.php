<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use function array_map;
use Beffroi\Saml2\Model\Validation\Authentication;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.6, M-2: how a protocol message was authenticated.
 */
final class AuthenticationTest extends TestCase
{
    /**
     * Section 5.6: an XML signature verified here, the binding's signature, or nothing, and no other case.
     */
    #[Test]
    public function itIsAnXmlSignatureTheBindingOrNothing(): void
    {
        // When / Then
        static::assertSame(
            ['XmlSignature', 'Binding', 'None'],
            array_map(
                static fn (Authentication $authentication): string => $authentication->name,
                Authentication::cases(),
            ),
        );
    }
}
