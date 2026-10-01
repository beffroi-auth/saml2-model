<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Support;

use Beffroi\Saml2\Model\Tests\Support\ResponseFixtureBuilder;
use function file_get_contents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.2, section 9.7: the response fixtures are built, never written by hand, and the command of their README
 * writes the committed bytes again.
 */
final class ResponseFixtureBuilderTest extends TestCase
{
    /**
     * Section 9.7: every response fixture on disk is what the builder writes, byte for byte.
     */
    #[Test]
    public function itBuildsTheCommittedFixtures(): void
    {
        // When
        $fixtures = ResponseFixtureBuilder::fixtures();

        // Then
        foreach ($fixtures as $path => $bytes) {
            static::assertSame(file_get_contents(__DIR__ . '/../../Fixture/' . $path), $bytes, $path);
        }
    }
}
