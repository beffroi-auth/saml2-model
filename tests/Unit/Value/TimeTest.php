<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Value\Time;
use DateTimeImmutable;
use DateTimeZone;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\TestCase;

/**
 * M-6, M-15: a time is an xs:dateTime in UTC with the Z designator (SAML Core §1.3.3), read to the microsecond and
 * written to the second.
 */
final class TimeTest extends TestCase
{
    /**
     * SAML Core §1.3.3, XML Schema Part 2 §3.2.7: the one lexical form, read to the microsecond.
     */
    #[Test]
    #[DataProvider('provideTimes')]
    public function itReadsATimeInUtcWithTheZDesignator(string $value, string $expected): void
    {
        // When
        $time = Time::read($value);

        // Then
        static::assertSame($expected, $time->format('Y-m-d\TH:i:s.u'));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function provideTimes(): iterable
    {
        yield 'to the second' => ['2026-09-30T12:34:56Z', '2026-09-30T12:34:56.000000'];
        yield 'one fractional digit' => ['2026-09-30T12:34:56.5Z', '2026-09-30T12:34:56.500000'];
        yield 'three fractional digits' => ['2026-09-30T12:34:56.789Z', '2026-09-30T12:34:56.789000'];
        yield 'six fractional digits' => ['2026-09-30T12:34:56.000001Z', '2026-09-30T12:34:56.000001'];
        yield 'seven fractional digits, truncated' => ['2026-09-30T12:34:56.1234567Z', '2026-09-30T12:34:56.123456'];
        yield 'nine fractional digits, truncated' => ['2026-09-30T12:34:56.999999999Z', '2026-09-30T12:34:56.999999'];
        yield 'the last second of a day' => ['2026-12-31T23:59:59Z', '2026-12-31T23:59:59.000000'];
        yield 'the first second of a day' => ['2026-01-01T00:00:00Z', '2026-01-01T00:00:00.000000'];
        yield '29 February of a leap year' => ['2024-02-29T08:00:00Z', '2024-02-29T08:00:00.000000'];
        yield '31 December of year 9999' => ['9999-12-31T23:59:59Z', '9999-12-31T23:59:59.000000'];
        yield '1 January of year 1' => ['0001-01-01T00:00:00Z', '0001-01-01T00:00:00.000000'];
    }

    /**
     * SAML Core §1.3.3: in UTC form, whatever the default zone of the process.
     */
    #[Test]
    public function itReadsATimeInUtc(): void
    {
        // When
        $time = Time::read('2026-09-30T12:34:56Z');

        // Then
        static::assertSame('UTC', $time->getTimezone()->getName());
    }

    /**
     * §9.2 row 26, M-6, SAML Core §1.3.3: no zone but Z, no hour 24, no leap second, at most nine fractional digits,
     * nothing around it; the message names the rule and carries nothing of the value (M-16).
     */
    #[Test]
    #[DataProvider('provideNotTheLexicalForm')]
    public function itRefusesWhatIsNotTheLexicalForm(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A time is not an xs:dateTime in UTC with the Z designator (M-6).');

        // When
        Time::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotTheLexicalForm(): iterable
    {
        yield 'without Z' => ['2026-09-30T12:34:56'];
        yield 'with +00:00' => ['2026-09-30T12:34:56+00:00'];
        yield 'with -00:00' => ['2026-09-30T12:34:56-00:00'];
        yield 'with an offset after Z' => ['2026-09-30T12:34:56Z+02:00'];
        yield 'at 24:00:00' => ['2026-09-30T24:00:00Z'];
        yield 'at second 60' => ['2016-12-31T23:59:60Z'];
        yield 'at minute 60' => ['2026-09-30T12:60:00Z'];
        yield 'with ten fractional digits' => ['2026-09-30T12:34:56.1234567890Z'];
        yield 'with a point and no fractional digit' => ['2026-09-30T12:34:56.Z'];
        yield 'with a leading space' => [' 2026-09-30T12:34:56Z'];
        yield 'with a trailing space' => ['2026-09-30T12:34:56Z '];
        yield 'with a trailing newline' => ["2026-09-30T12:34:56Z\n"];
        yield 'with a lowercase z' => ['2026-09-30T12:34:56z'];
        yield 'with a lowercase t' => ['2026-09-30t12:34:56Z'];
        yield 'with a space for T' => ['2026-09-30 12:34:56Z'];
        yield 'with a five-digit year' => ['12026-09-30T12:34:56Z'];
        yield 'with a two-digit year' => ['26-09-30T12:34:56Z'];
        yield 'with a negative year' => ['-2026-09-30T12:34:56Z'];
        yield 'without seconds' => ['2026-09-30T12:34Z'];
        yield 'a date alone' => ['2026-09-30'];
        yield 'with a one-digit month' => ['2026-9-30T12:34:56Z'];
        yield 'empty' => [''];
    }

    /**
     * §9.2 row 26, M-6: a date that no calendar has.
     */
    #[Test]
    #[DataProvider('provideNotADateOfTheCalendar')]
    public function itRefusesWhatIsNotADateOfTheCalendar(string $value): void
    {
        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A time is not a date of the calendar (M-6).');

        // When
        Time::read($value);
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function provideNotADateOfTheCalendar(): iterable
    {
        yield 'on 30 February' => ['2026-02-30T00:00:00Z'];
        yield 'on 29 February of a common year' => ['2026-02-29T00:00:00Z'];
        yield 'on 31 April' => ['2026-04-31T00:00:00Z'];
        yield 'in month 13' => ['2026-13-01T00:00:00Z'];
        yield 'in month 00' => ['2026-00-01T00:00:00Z'];
        yield 'on day 00' => ['2026-09-00T00:00:00Z'];
        yield 'in year 0000' => ['0000-01-01T00:00:00Z'];
    }

    /**
     * M-15: in UTC, to the second, with the Z designator.
     */
    #[Test]
    #[DataProvider('provideWrittenTimes')]
    public function itWritesATimeInUtcToTheSecond(DateTimeImmutable $time, string $expected): void
    {
        // When / Then
        static::assertSame($expected, Time::write($time));
    }

    /**
     * @return iterable<string, array{DateTimeImmutable, string}>
     */
    public static function provideWrittenTimes(): iterable
    {
        yield 'a time in UTC' => [new DateTimeImmutable('2026-09-30T12:34:56Z'), '2026-09-30T12:34:56Z'];
        yield 'a time with microseconds' => [
            new DateTimeImmutable('2026-09-30T12:34:56.999999Z'),
            '2026-09-30T12:34:56Z',
        ];
        yield 'a time in another zone' => [
            new DateTimeImmutable('2026-09-30T12:34:56Z')->setTimezone(new DateTimeZone('Europe/Paris')),
            '2026-09-30T12:34:56Z',
        ];
    }

    /**
     * M-15: what is written is what is read; the reader reads it back to the second.
     */
    #[Test]
    public function itReadsBackWhatItWrites(): void
    {
        // Given
        $time = new DateTimeImmutable('2026-09-30T12:34:56Z');

        // When
        $read = Time::read(Time::write($time));

        // Then
        static::assertEquals($time, $read);
    }

    /**
     * M-15: a year the reader would refuse is never written.
     */
    #[Test]
    #[DataProvider('provideUnwritableYears')]
    public function itRefusesToWriteWhatItWouldNotRead(int $year): void
    {
        // Given
        $time = new DateTimeImmutable('2026-09-30T12:34:56Z')->setDate($year, 1, 1);

        // Then
        $this->expectException(MalformedMessage::class);
        $this->expectExceptionMessageIs('A time is not an xs:dateTime in UTC with the Z designator (M-6).');

        // When
        Time::write($time);
    }

    /**
     * @return iterable<string, array{int}>
     */
    public static function provideUnwritableYears(): iterable
    {
        yield 'year 10000' => [10_000];
        yield 'year -1' => [-1];
    }
}
