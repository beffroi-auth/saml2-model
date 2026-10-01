<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Exception;

use Beffroi\Saml2\Model\Exception\AudienceMismatch;
use Beffroi\Saml2\Model\Exception\MessageRefused;
use function class_parents;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 5.8, M-8: an audience that is not ours, refused with the rest of what the model refuses.
 */
final class AudienceMismatchTest extends TestCase
{
    #[Test]
    public function itIsAMessageRefused(): void
    {
        // When / Then
        static::assertContains(MessageRefused::class, class_parents(AudienceMismatch::class));
    }
}
