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
 * SAML Core §1.3.3, M-6, M-15
 *
 * No whitespace is collapsed, although XML Schema would: two readers that disagree on it are a differential.
 */
final readonly class Time
{
    private const string PATTERN = '~^(?<datetime>(?<year>\d{4})-(?<month>\d{2})-(?<day>\d{2})T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d)(?:\.(?<fraction>\d{1,9}))?Z\z~';

    /**
     * @throws MalformedMessage
     */
    public static function read(string $value): DateTimeImmutable
    {
        if (preg_match(self::PATTERN, $value, $parts, PREG_UNMATCHED_AS_NULL) !== 1) {
            throw new MalformedMessage('A time is not an xs:dateTime in UTC with the Z designator (M-6).');
        }
        // "!" resets every field the format does not name, rather than filling it from the clock.
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
     * @throws MalformedMessage when the year is not of four digits
     */
    public static function write(DateTimeImmutable $time): string
    {
        $written = $time->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z');
        self::read($written);

        return $written;
    }
}
