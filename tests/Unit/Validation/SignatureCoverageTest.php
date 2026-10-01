<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use function array_map;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.5, M-2: which signature covered an accepted assertion.
 */
final class SignatureCoverageTest extends TestCase
{
    /**
     * Section 5.5, SAML Profiles §4.1.4.5 as corrected by E26: the assertion's, the response's, or both, and no other
     * case.
     */
    #[Test]
    public function itIsTheAssertionsTheResponsesOrBoth(): void
    {
        // When / Then
        static::assertSame(
            ['Assertion', 'Response', 'AssertionAndResponse'],
            array_map(
                static fn (SignatureCoverage $coverage): string => $coverage->name,
                SignatureCoverage::cases(),
            ),
        );
    }
}
