<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Metadata;

use function array_map;
use Beffroi\Saml2\Model\Metadata\Binding;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.3, M-5: the two bindings an endpoint is kept on (SAML Bindings §3.4, §3.5).
 */
final class BindingTest extends TestCase
{
    /**
     * SAML Bindings §3.4.1 and §3.5.1: the URIs of HTTP-Redirect and HTTP-POST, and no other case.
     */
    #[Test]
    public function itIsHttpRedirectAndHttpPost(): void
    {
        // When / Then
        static::assertSame(
            [
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect',
                'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
            ],
            array_map(static fn (Binding $binding): string => $binding->value, Binding::cases()),
        );
    }
}
