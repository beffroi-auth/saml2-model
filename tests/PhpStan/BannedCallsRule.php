<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Tests\PhpStan;

use PhpParser\Node;
use PhpParser\Node\Expr\CallLike;
use PhpParser\Node\Expr\FuncCall;
use PhpParser\Node\Expr\MethodCall;
use PhpParser\Node\Expr\New_;
use PhpParser\Node\Expr\NullsafeMethodCall;
use PhpParser\Node\Expr\StaticCall;
use PhpParser\Node\Identifier;
use PhpParser\Node\Name;
use PhpParser\Node\Stmt\Class_;
use PHPStan\Analyser\Scope;
use PHPStan\Rules\IdentifierRuleError;
use PHPStan\Rules\Rule;
use PHPStan\Rules\RuleErrorBuilder;
use function array_any;
use function rtrim;
use function sprintf;
use function str_ends_with;
use function str_starts_with;
use function strtolower;

/**
 * Section 8 of the specification: the methods of the Dom API and the functions never called, in src/ and in tests/.
 * The model confines none of them to a file, as xml-security confines createFromString() to its Loader: here each is
 * banned everywhere. A function name ending with * bans the prefix (every openssl_* function). A method of a class of
 * this package is not the Dom method of the same name (ResponseValidator::validate() is not Dom\Document::validate()),
 * so a call whose receiver is known to be one is let through. A dynamic call or a dynamic instantiation would escape
 * the rule, so both are refused too. ekino/phpstan-banned-code bans a function by the name as written; this rule reads
 * the name as resolved, whatever its case.
 *
 * @implements Rule<CallLike>
 */
final class BannedCallsRule implements Rule
{
    private const string PACKAGE = 'beffroi\\saml2\\model\\';

    /**
     * @var array<string, string> the lowercased method names, mapped to the spelling of the configuration
     */
    private array $methods = [];

    /**
     * @var array<string, string> the lowercased function names, mapped to the spelling of the configuration
     */
    private array $functions = [];

    /**
     * @var array<string, string> the lowercased function prefixes, mapped to the spelling of the configuration
     */
    private array $prefixes = [];

    /**
     * @param list<string> $methods
     * @param list<string> $functions each a name, or a prefix followed by *
     */
    public function __construct(array $methods, array $functions)
    {
        foreach ($methods as $method) {
            $this->methods[strtolower($method)] = $method;
        }
        foreach ($functions as $function) {
            if (str_ends_with($function, '*')) {
                $this->prefixes[strtolower(rtrim($function, '*'))] = $function;
                continue;
            }
            $this->functions[strtolower($function)] = $function;
        }
    }

    public function getNodeType(): string
    {
        return CallLike::class;
    }

    /**
     * @return list<IdentifierRuleError>
     */
    public function processNode(Node $node, Scope $scope): array
    {
        if ($node instanceof New_) {
            return (
                $node->class instanceof Name || $node->class instanceof Class_
                    ? []
                    : [$this->error('A dynamic instantiation escapes the review: name the class.')]
            );
        }
        if ($node instanceof FuncCall) {
            if (! $node->name instanceof Name) {
                return [$this->error('A dynamic call escapes the review: name the function.')];
            }

            return $this->banned($this->function($node->name));
        }
        if (! $node instanceof MethodCall && ! $node instanceof NullsafeMethodCall && ! $node instanceof StaticCall) {
            return [];
        }
        if (! $node->name instanceof Identifier) {
            return [$this->error('A dynamic call escapes the review: name the method.')];
        }
        $method = $this->methods[$node->name->toLowerString()] ?? null;
        if ($method === null || $this->ofThePackage($node, $scope)) {
            return [];
        }

        return $this->banned($method . '()');
    }

    /**
     * The banned function $name calls, as the configuration spells it or, for a banned prefix, as written; else null.
     */
    private function function(Name $name): ?string
    {
        $function = $this->functions[$name->toLowerString()] ?? null;
        if ($function !== null) {
            return $function . '()';
        }
        foreach ($this->prefixes as $prefix => $spelling) {
            if (str_starts_with($name->toLowerString(), $prefix)) {
                return sprintf('%s(), of %s,', $name->toString(), $spelling);
            }
        }

        return null;
    }

    /**
     * Whether the receiver of the call is a class of this package, as far as PHPStan knows its type.
     */
    private function ofThePackage(MethodCall|NullsafeMethodCall|StaticCall $node, Scope $scope): bool
    {
        if ($node instanceof StaticCall) {
            return (
                $node->class instanceof Name
                && str_starts_with(strtolower($scope->resolveName($node->class)), self::PACKAGE)
            );
        }

        return array_any(
            $scope->getType($node->var)->getObjectClassNames(),
            static fn (string $class): bool => str_starts_with(strtolower($class), self::PACKAGE),
        );
    }

    /**
     * @return list<IdentifierRuleError>
     */
    private function banned(?string $call): array
    {
        if ($call === null) {
            return [];
        }

        return [$this->error(sprintf('%s is never called: section 8 of the specification bans it.', $call))];
    }

    private function error(string $message): IdentifierRuleError
    {
        return RuleErrorBuilder::message($message)->identifier('beffroi.bannedCall')->nonIgnorable()->build();
    }
}
