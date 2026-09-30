<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Validation;

use Beffroi\Saml2\Model\Internal\Assertion\AssertionReader;
use Beffroi\Saml2\Model\Tests\Unit\Internal\Assertion\AssertionFixtures;
use Beffroi\Saml2\Model\Validation\AcceptedAssertion;
use Beffroi\Saml2\Model\Validation\SignatureCoverage;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.5: what the validator of a response accepted, values the consumer reads without the document.
 */
final class AcceptedAssertionTest extends TestCase
{
    use AssertionFixtures;

    /**
     * Section 5.5: the ID of the response, the assertion and its coverage, as given.
     */
    #[Test]
    public function itKeepsItsValues(): void
    {
        // Given
        $assertion = AssertionReader::read($this->document('behaviour/assertion-valid-accepted.xml'), $this->context());

        // When
        $accepted = new AcceptedAssertion('_response', $assertion, SignatureCoverage::Response);

        // Then
        static::assertSame(
            ['_response', $assertion, SignatureCoverage::Response],
            [$accepted->responseId, $accepted->assertion, $accepted->coverage],
        );
    }
}
