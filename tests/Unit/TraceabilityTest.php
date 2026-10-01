<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit;

use function array_diff;
use function array_keys;
use Beffroi\Saml2\Model\Tests\Support\Traceability;
use function dirname;
use function implode;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * Section 9.7: the tests are the proof and the specification is the law. Every invariant of section 4 of
 * spec/model.md, every row of the hostile corpus of section 9.2 and every row of the behaviour corpus of section 9.3
 * is cited by the docblock of at least one test. The rows are counted in the specification itself, so that a row added
 * there without a test fails here.
 */
final class TraceabilityTest extends TestCase
{
    private Traceability $traceability;

    protected function setUp(): void
    {
        $this->traceability = new Traceability(dirname(__DIR__, 2) . '/spec/model.md', __DIR__);
    }

    /**
     * Section 4: M-1 to M-17, each cited by a test docblock.
     */
    #[Test]
    public function everyInvariantIsCitedByATest(): void
    {
        // Given
        $invariants = $this->traceability->invariants();
        static::assertCount(17, $invariants);

        // When
        $uncited = array_diff($invariants, $this->traceability->citedInvariants());

        // Then
        static::assertSame([], $uncited, 'Invariants no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.2: every row of the hostile corpus, cited as "§9.2 row N".
     */
    #[Test]
    public function everyRowOfTheHostileCorpusIsCitedByATest(): void
    {
        // Given
        $rows = $this->traceability->tableRows('### 9.2 Hostile corpus');
        static::assertCount(36, $rows);

        // When
        $uncited = array_diff(array_keys($rows), $this->traceability->citedRows('9.2'));

        // Then
        static::assertSame([], $uncited, 'Rows of section 9.2 no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.3: every row of the behaviour corpus, cited as "§9.3 row N".
     */
    #[Test]
    public function everyRowOfTheBehaviourCorpusIsCitedByATest(): void
    {
        // Given
        $rows = $this->traceability->tableRows('### 9.3 Behaviour corpus');
        static::assertCount(19, $rows);

        // When
        $uncited = array_diff(array_keys($rows), $this->traceability->citedRows('9.3'));

        // Then
        static::assertSame([], $uncited, 'Rows of section 9.3 no test cites: ' . implode(', ', $uncited));
    }

    /**
     * Section 9.7: a citation names a row the table has, never one past its end.
     */
    #[Test]
    public function everyCitedRowExists(): void
    {
        // Given
        $hostile = array_keys($this->traceability->tableRows('### 9.2 Hostile corpus'));
        $behaviour = array_keys($this->traceability->tableRows('### 9.3 Behaviour corpus'));

        // When
        $unknown = [
            ...array_diff($this->traceability->citedRows('9.2'), $hostile),
            ...array_diff($this->traceability->citedRows('9.3'), $behaviour),
        ];

        // Then
        static::assertSame([], $unknown, 'Rows cited that the tables do not have: ' . implode(', ', $unknown));
    }
}
