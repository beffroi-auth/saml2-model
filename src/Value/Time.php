<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Value;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use function checkdate;
use DateTimeImmutable;
use DateTimeZone;
use const PREG_UNMATCHED_AS_NULL;
use function preg_match;
use function str_pad;
use function substr;

/**
 * A SAML time (M-6): an xs:dateTime in UTC with the Z designator and no other zone (SAML Core §1.3.3), a four-digit
 * year, a date of the calendar, an hour from 00 to 23 (no 24:00:00), a minute and a second from 00 to 59 (no leap
 * second), at most nine fractional digits, kept to the microsecond; nothing around it, although XML Schema collapses
 * whitespace there, since two readers that disagree on it are a differential. Written in UTC to the second (M-15).
 */
final readonly class Time
{
    private const string PATTERN = '~^(?<datetime>(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)(?:\.(?<fraction>\d{1,9}))?Z\z~';

    /**
     * @throws MalformedMessage when the value is not of the lexical form above, or not a date of the calendar (M-6)
     */
    public static function read(string $value): DateTimeImmutable
    {
        if (preg_match(self::PATTERN, $value, $parts, PREG_UNMATCHED_AS_NULL) !== 1) {
            throw new MalformedMessage('A time is not an xs:dateTime in UTC with the Z designator (M-6).');
        }
        // "!" resets every field the format does not name, rather than filling it from the clock; createFromFormat()
        // cannot fail on what the pattern and checkdate() accepted, and its false joins the calendar's refusal
        $utc = new DateTimeZone('UTC');
        $time = checkdate((int) $parts['month'], (int) $parts['day'], (int) $parts['year'])
            ? DateTimeImmutable::createFromFormat('!Y-m-d\TH:i:s', $parts['datetime'], $utc)
            : false;
        if ($time === false) {
            throw new MalformedMessage('A time is not a date of the calendar (M-6).');
        }

        return $time->setMicrosecond((int) str_pad(substr($parts['fraction'] ?? '', 0, 6), 6, '0'));
    }

    /**
     * In UTC, to the second, with the Z designator (M-15).
     *
     * @throws MalformedMessage when the year is not of four digits, which the reader would refuse (M-15)
     */
    public static function write(DateTimeImmutable $time): string
    {
        $written = $time->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
        self::read($written);

        return $written;
    }
}
