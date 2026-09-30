<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\Unit\Exception;

use SensitiveParameter;
use function array_filter;
use function array_map;
use function array_values;
use function basename;
use function count;
use function dirname;
use function file_get_contents;
use function glob;
use function in_array;
use PhpToken;
use PHPUnit\Framework\Attributes\Test;
use PHPUnit\Framework\Attributes\TestWith;
use PHPUnit\Framework\TestCase;
use function preg_match;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;
use function sprintf;
use function strlen;
use function substr;
use const T_CONSTANT_ENCAPSED_STRING;
use const T_DOUBLE_COLON;
use const T_NEW;
use const T_STRING;
use const T_VARIABLE;

/**
 * §9.3 row 16, M-16: every message of a MessageRefused, read on the source of src/, ends with the rule that refused, in
 * parentheses, and is written in the code, a literal or the format of a sprintf() whose arguments are names and bounds
 * of the schema, never a value read from a message. Counts::check() and Schema::unsupported() pass on the message their
 * callers write, which is read at each call; UnsuccessfulResponse writes its own, which its test reads (§9.3 row 14).
 * That no message carries an ID, a URL, an entity ID or a NameID of the input is asserted by every refusal test of the
 * readers (assertCarriesNothingOf()).
 */
final class RefusalMessagesTest extends TestCase
{
    /**
     * The methods that throw the message their caller writes, and the files they live in.
     */
    private const array PASSING_ON = ['Counts::check', 'Schema::unsupported'];

    private const array PASSING_ON_FILES = ['Value/Counts.php', 'Internal/Schema.php'];

    /**
     * §9.3 row 16, M-16: the message of every refusal of src/ ends with "(M-n).", "(section n)." or the section of a
     * SAML specification.
     */
    #[Test]
    public function everyRefusalNamesItsRule(): void
    {
        // Given
        $messages = [];
        foreach ($this->sources() as $file => $source) {
            foreach ($this->messages($source) as $message) {
                $messages[] = [$file, $message];
            }
        }

        // When
        $unnamed = array_values(array_filter(
            $messages,
            static fn (array $message): bool => ! self::namesItsRule($message[1]),
        ));

        // Then
        static::assertGreaterThan(100, count($messages));
        static::assertSame([], array_map(static fn (array $message): string => sprintf(
            '%s: %s',
            $message[0],
            $message[1],
        ), $unnamed));
    }

    /**
     * The scan finds the messages of a refusal, built as the source builds them, and marks one it cannot read.
     *
     * @param list<string> $expected
     */
    #[Test]
    #[TestWith([
        "<?php throw new MalformedMessage('The version is not 2.0 (M-6).');",
        ['The version is not 2.0 (M-6).'],
    ], 'a literal')]
    #[TestWith([
        "<?php throw new MalformedMessage(sprintf('The %s holds no %s (M-4).', \$a, \$b));",
        ['The %s holds no %s (M-4).'],
    ], 'a format')]
    #[TestWith([
        "<?php Counts::check(count(\$x), Counts::AUDIENCES, 'An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).');",
        ['An AudienceRestriction holds more than 16 Audience, the bound of section 7 (M-17).'],
    ], 'a count')]
    #[TestWith(["<?php throw new IssuerMismatch(\$message);", ['<not a literal>']], 'a variable')]
    #[TestWith(["<?php throw new InvalidArgumentException(\$message);", []], 'a programming error')]
    public function itFindsTheMessagesOfARefusal(string $source, array $expected): void
    {
        // When / Then
        static::assertSame($expected, $this->messages($source));
    }

    private static function namesItsRule(string $message): bool
    {
        return preg_match('~\((?:M-\d+|section \d+(?:\.\d+)*|SAML [^()]+)\)\.\z~', $message) === 1;
    }

    /**
     * The messages the source gives a refusal: the first argument of new <MessageRefused subclass>(...), a literal or
     * the format of sprintf(), and the literal of each Counts::check() and Schema::unsupported(); anything else is
     * "<not a literal>".
     *
     * @return list<string>
     */
    private function messages(string $source): array
    {
        $tokens = array_values(array_filter(
            PhpToken::tokenize($source),
            static fn (#[SensitiveParameter] PhpToken $phpToken): bool => ! $phpToken->isIgnorable(),
        ));
        $refusals = $this->refusals();
        $messages = [];
        foreach ($tokens as $index => $token) {
            if ($token->is(T_NEW) && in_array($tokens[$index + 1]->text ?? '', $refusals, true)) {
                $messages[] = $this->argument($tokens, $index + 3);
            }
            if (
                $token->is(T_STRING)
                && in_array($token->text . '::' . ($tokens[$index + 2]->text ?? ''), self::PASSING_ON, true)
                && ($tokens[$index + 1] ?? null)?->is(T_DOUBLE_COLON) === true
            ) {
                $messages[] = $this->lastLiteral($tokens, $index + 3);
            }
        }

        return $messages;
    }

    /**
     * The message at $index, the first token of an argument: a literal, or the literal format of sprintf().
     *
     * @param list<PhpToken> $tokens
     */
    private function argument(array $tokens, int $index): string
    {
        $token = $tokens[$index] ?? null;
        if ($token?->text === 'sprintf') {
            $token = $tokens[$index + 2] ?? null;
        }

        return $token?->is(T_CONSTANT_ENCAPSED_STRING) === true ? $this->unquote($token->text) : '<not a literal>';
    }

    /**
     * The last literal argument of the call whose parenthesis opens at $index, the format of a sprintf() included.
     *
     * @param list<PhpToken> $tokens
     */
    private function lastLiteral(array $tokens, int $index): string
    {
        $depth = 0;
        $literal = '<not a literal>';
        $counter = count($tokens);
        for ($position = $index; $position < $counter; ++$position) {
            $text = $tokens[$position]->text;
            if ($text === '(') {
                ++$depth;
            }
            if ($text === ')') {
                --$depth;
            }
            if ($depth === 0) {
                break;
            }
            if ($tokens[$position]->is(T_CONSTANT_ENCAPSED_STRING)) {
                $literal = $this->unquote($tokens[$position]->text);
            }
            if ($tokens[$position]->is(T_VARIABLE) && $depth === 1 && ($tokens[$position + 1]->text ?? '') === ')') {
                $literal = '<not a literal>';
            }
        }

        return $literal;
    }

    private function unquote(string $literal): string
    {
        return substr($literal, 1, strlen($literal) - 2);
    }

    /**
     * The short names of the MessageRefused subclasses, the files of src/Exception/.
     *
     * @return list<string>
     */
    private function refusals(): array
    {
        $files = glob(dirname(__DIR__, 3) . '/src/Exception/*.php');
        static::assertIsArray($files);

        return array_values(array_filter(
            array_map(static fn (string $file): string => basename($file, '.php'), $files),
            static fn (string $name): bool => ! in_array($name, ['MessageRefused', 'UnsuccessfulResponse'], true),
        ));
    }

    /**
     * @return array<string, string> each PHP file of src/, its path relative to src/ to its source, the two that pass
     *                               on the message their callers write left aside
     */
    private function sources(): array
    {
        $directory = dirname(__DIR__, 3) . '/src';
        $sources = [];
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(
            $directory,
            RecursiveDirectoryIterator::SKIP_DOTS,
        ));
        foreach ($iterator as $file) {
            if (! $file instanceof SplFileInfo || $file->getExtension() !== 'php') {
                continue;
            }
            $path = substr($file->getPathname(), strlen($directory) + 1);
            if (in_array($path, self::PASSING_ON_FILES, true)) {
                continue;
            }
            $source = file_get_contents($file->getPathname());
            static::assertIsString($source);
            $sources[$path] = $source;
        }

        return $sources;
    }
}
