<?php

declare(strict_types=1);

/*
 * The quality tools, what the CI runs on every push (.github/workflows/ci.yml): each one in the phpqa image
 * when Docker is available, directly when already inside a container (the CI) or without Docker. PHP 8.5 by
 * default, 8.4 with PHP_VERSION=8.4, the two versions the CI runs.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsRawTokens;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\io;
use function Castor\run;

/**
 * The files section 9 of the specification accepts only with no escaped mutant: "castor infect" mutates them
 * whole, uncovered lines included, and fails under a hundred percent. A file joins the list in the commit that
 * creates it, never before: a listed file missing from the tree is an error.
 */
const INFECTION_STRICT_FILES = [
    // Section 5.8: the refusals, and the status a refused response carries (M-13, M-16).
    'src/Exception/MessageRefused.php',
    'src/Exception/MalformedMessage.php',
    'src/Exception/Unsupported.php',
    'src/Exception/SignatureRequired.php',
    'src/Exception/IssuerMismatch.php',
    'src/Exception/AudienceMismatch.php',
    'src/Exception/RecipientMismatch.php',
    'src/Exception/DestinationMismatch.php',
    'src/Exception/UnknownEndpoint.php',
    'src/Exception/InResponseToMismatch.php',
    'src/Exception/Replayed.php',
    'src/Exception/InvalidNameId.php',
    'src/Exception/IndeterminateCondition.php',
    'src/Exception/UnsuccessfulResponse.php',
    'src/Exception/OutsideValidityWindow.php',
    'src/Exception/LimitExceeded.php',
    'src/Protocol/StatusCode.php',
    'src/Protocol/SecondLevelStatusCode.php',
    'src/Protocol/Status.php',
    // Section 9: the lexical forms of M-6 and SamlId, every file of src/Value/.
    'src/Value/Time.php',
    'src/Value/Boolean.php',
    'src/Value/SamlId.php',
    'src/Value/Uri.php',
    'src/Value/Version.php',
    // Section 9: NameId, the rule of each format (M-12).
    'src/Assertion/NameId.php',
    // Section 9: the bounds of time the validators and the metadata reader share (M-7).
    'src/Validation/TimeBounds.php',
    // Section 9: IndexedEndpoints, the default endpoint and the searches of M-9.
    'src/Metadata/IndexedEndpoints.php',
    // Section 9: the strict readers of metadata and the rules its roles share.
    'src/Internal/Metadata/RoleRules.php',
    // Section 9, each added by the story that writes it:
    // src/Metadata/MetadataReader.php;
    // the strict readers and the selection of the signed element, every file of src/Internal/;
    // the validators, every other file of src/Validation/.
];

/**
 * The PHP version of the phpqa image: 8.5, what the package runs on, unless PHP_VERSION says otherwise.
 */
function php_version(): string
{
    return getenv('PHP_VERSION') ?: '8.5';
}

/**
 * Runs a command in the phpqa image, or directly when already inside a container (CI) or without Docker.
 * The environment applies in both cases. $inherited names variables of this process's own environment, a
 * credential: they cross into the container by their name alone, docker reading the value from the environment
 * it inherits, so that the value is on no command line and in no context Castor prints at -vvv.
 *
 * @param array<string> $command
 * @param array<string, string> $environment
 * @param list<string> $inherited
 */
function phpqa(array $command, array $environment = [], array $inherited = []): void
{
    $inContainer = file_exists('/.dockerenv');
    $hasDocker = trim(shell_exec('command -v docker') ?? '') !== '';
    $environment += [
        'XDEBUG_MODE' => 'off',
        'COMPOSER_PROCESS_TIMEOUT' => '0',
    ];

    if (! $hasDocker || $inContainer) {
        run($command, context: context()->withEnvironment($environment));
        return;
    }

    if (! is_dir(getcwd() . '/tmp-phpqa')) {
        mkdir(getcwd() . '/tmp-phpqa');
    }

    $dockerOptions = [
        '--rm',
        '--init',
        stream_isatty(\STDOUT) ? '-it' : '-i',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-v',
        getcwd() . ':/project',
        '-v',
        getcwd() . '/tmp-phpqa:/project/tmp-phpqa',
        '-w',
        '/project',
        '-e',
        'PHP_INI_SCAN_DIR=/usr/local/etc/php/conf.d',
        '-e',
        'PHP_INI_ENTRY=sys_temp_dir=/project/tmp-phpqa',
        // The checkout belongs to the host user, the container runs as that uid without a name: git would refuse
        // the "dubious ownership", and Infection's --git-diff-lines needs git to work.
        '-e',
        'GIT_CONFIG_COUNT=1',
        '-e',
        'GIT_CONFIG_KEY_0=safe.directory',
        '-e',
        'GIT_CONFIG_VALUE_0=/project',
    ];
    // In a git worktree, .git is a file naming a directory of the main checkout, outside the mount: that directory is
    // mounted at its own path, so that git works in the container (Composer's root version, Infection's diff).
    $gitDirectory = trim(capture(
        ['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
        context()->withQuiet()->withAllowFailure(),
        onFailure: '',
    ));
    if ($gitDirectory !== '' && ! str_starts_with($gitDirectory, getcwd() . '/')) {
        $dockerOptions[] = '-v';
        $dockerOptions[] = $gitDirectory . ':' . $gitDirectory;
    }
    foreach ($environment as $name => $value) {
        $dockerOptions[] = '-e';
        $dockerOptions[] = $name . '=' . $value;
    }
    foreach ($inherited as $name) {
        $dockerOptions[] = '-e';
        $dockerOptions[] = $name;
    }

    run([
        'docker',
        'run',
        ...$dockerOptions,
        sprintf('ghcr.io/spomky-labs/phpqa:%s', php_version()),
        ...$command,
    ]);
}

#[AsTask(description: 'Update the PHPQA Docker image')]
function phpqa_update(): void
{
    run(['docker', 'pull', 'ghcr.io/spomky-labs/phpqa:' . php_version()]);
}

#[AsTask(
    description: 'Install the dependencies with Composer in the phpqa image; beffroi-php/xml-security is private and has no tag (spec/model.md section 12): the token of the GitHub CLI reaches Composer through COMPOSER_AUTH, in the environment only',
)]
function install(): void
{
    $environment = [
        // Composer's home and cache stay in the ignored tmp-phpqa/: the container user has no home of its own.
        'COMPOSER_HOME' => 'tmp-phpqa/composer',
        'COMPOSER_CACHE_DIR' => 'tmp-phpqa/composer/cache',
    ];
    $command = ['composer', 'install', '--no-interaction', '--no-progress', '--prefer-dist'];
    $auth = getenv('COMPOSER_AUTH');
    if (is_string($auth) && $auth !== '') {
        // The CI, or a developer who set it: passed on as it is.
        phpqa($command, $environment, ['COMPOSER_AUTH']);

        return;
    }
    $auth = github_cli_auth();
    if ($auth === null) {
        phpqa($command, $environment);

        return;
    }
    // In this process's environment for the time of the install, which Castor does not print, never in its context.
    putenv('COMPOSER_AUTH=' . $auth);
    $_ENV['COMPOSER_AUTH'] = $auth;
    try {
        phpqa($command, $environment, ['COMPOSER_AUTH']);
    } finally {
        putenv('COMPOSER_AUTH');
        unset($_ENV['COMPOSER_AUTH']);
    }
}

/**
 * The COMPOSER_AUTH document around the token of the GitHub CLI, or null without the CLI or its token, and Composer
 * asks GitHub anonymously. The token is never printed and never written to a file.
 */
function github_cli_auth(): ?string
{
    if (trim(shell_exec('command -v gh') ?? '') === '') {
        io()->warning('Neither COMPOSER_AUTH nor the GitHub CLI: beffroi-php/xml-security is fetched anonymously.');

        return null;
    }
    $token = trim(capture(['gh', 'auth', 'token'], context()->withQuiet()->withAllowFailure(), onFailure: ''));
    if ($token === '') {
        io()->warning('The GitHub CLI holds no token ("gh auth login"): beffroi-php/xml-security is fetched anonymously.');

        return null;
    }

    return json_encode(['github-oauth' => ['github.com' => $token]], \JSON_THROW_ON_ERROR);
}

#[AsTask(description: 'Run PHPUnit tests with coverage', ignoreValidationErrors: true)]
function phpunit(#[AsRawTokens] array $args = []): void
{
    phpqa(
        [
            'composer',
            'exec',
            '--',
            'phpunit',
            '--coverage-xml',
            '.ci-tools/coverage',
            '--log-junit=.ci-tools/coverage/junit.xml',
            '--configuration',
            '.ci-tools/phpunit.xml.dist',
            '--display-warnings',
            '--display-deprecations',
            ...$args,
        ],
        [
            'XDEBUG_MODE' => 'coverage',
        ],
    );
}

/*
 * Mago (https://mago.carthage.software/), the toolchain of Carthage Software: one Rust binary, already installed
 * in the phpqa image (/tools/mago), configured by mago.toml at the root of the repository. It holds the formatter
 * and the linter. Its analyzer is not PHPStan's equal and replaces nothing.
 */

#[AsTask(description: 'Check the formatting with Mago')]
function mago_format(): void
{
    phpqa(['mago', 'format', '--check']);
}

#[AsTask(description: 'Format the code with Mago')]
function mago_format_fix(): void
{
    phpqa(['mago', 'format']);
}

#[AsTask(description: 'Run the Mago linter')]
function mago_lint(): void
{
    phpqa(['mago', 'lint']);
}

#[AsTask(description: 'Apply the fixes the Mago linter offers')]
function mago_lint_fix(): void
{
    phpqa(['mago', 'lint', '--fix']);
}

#[AsTask(description: 'Run Rector dry-run')]
function rector(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--dry-run', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run Rector with fix')]
function rector_fix(): void
{
    phpqa(['composer', 'exec', '--', 'rector', 'process', '--config', '.ci-tools/rector.php']);
}

#[AsTask(description: 'Run PHPStan at level max, with no baseline, and the banned code of section 8')]
function phpstan(): void
{
    phpqa([
        'composer',
        'exec',
        '--',
        'phpstan',
        'analyse',
        '--error-format=github',
        '--configuration=.ci-tools/phpstan.neon',
    ]);
}

#[AsTask(
    description: 'Run Deptrac between the layers of section 10: Value below Assertion, Protocol and Metadata, below Validation and Writing; the public classes of Core and Dsig, psr/clock, nothing of HTTP',
)]
function deptrac(): void
{
    phpqa([
        'deptrac',
        'analyse',
        '--config-file=.ci-tools/deptrac.yaml',
        '--cache-file=tmp-phpqa/.deptrac.cache',
        '--no-progress',
    ]);
}

#[AsTask(description: 'Run PHP parallel linter')]
function lint(): void
{
    // The interoperability projects of section 9.5 are throwaway Composer projects run in their own containers.
    phpqa(['composer', 'exec', '--', 'parallel-lint', 'src', 'tests', '--exclude', 'tests/Interop']);
}

#[AsTask(description: 'Validate composer.json strictly and check the PSR-4 layout')]
function composer_validate(): void
{
    phpqa(['composer', 'validate', '--strict']);
    phpqa(['composer', 'dump-autoload', '--optimize', '--strict-psr']);
}

#[AsTask(
    description: 'Run Infection on the coverage of a fresh PHPUnit run. By default the files of section 9 are mutated whole and no escaped mutant is allowed; --diff mutates the lines added or modified since --base over the whole source, the shape of every CI run on the rest; --all mutates the whole source with no minimum',
)]
function infect(
    #[AsOption(
        description: 'Mutate only the lines added or modified since --base, committed or not, over the whole source',
    )]
    bool $diff = false,
    #[AsOption(description: 'Mutate the whole source, informative only')]
    bool $all = false,
    #[AsOption(
        description: 'The branch or commit the diff of --diff is taken from; Infection narrows it to the merge base with HEAD',
    )]
    string $base = 'origin/main',
    #[AsOption(
        description: 'Mutate these files only, comma-separated, with no escaped mutant allowed: the strict run narrowed while the tree is being built',
    )]
    string $files = '',
    #[AsOption(description: 'Mutant processes run in parallel; "max" is the number of cores minus one')]
    string $threads = 'max',
    #[AsOption(
        description: 'Reuse the coverage of the last "castor phpunit" in .ci-tools/coverage instead of running the tests again; it must come from the same source and the same paths',
    )]
    bool $reuseCoverage = false,
): void {
    // The XML coverage and the JUnit report of a "castor phpunit" run are what Infection reads from .ci-tools/coverage.
    if ($reuseCoverage && (! is_file('.ci-tools/coverage/index.xml') || ! is_file('.ci-tools/coverage/junit.xml'))) {
        io()->error('No coverage to reuse in .ci-tools/coverage: run "castor phpunit" first, or drop --reuse-coverage.');
        exit(1);
    }
    $scope = infection_scope($diff, $all, $base, $files);
    if ($scope === null) {
        io()->warning('None of the files of section 9 exists yet: nothing to mutate.');
        return;
    }
    if (! $reuseCoverage) {
        phpunit();
    }

    $options = [
        '--coverage=.ci-tools/coverage',
        '--skip-initial-tests',
        '--threads=' . $threads,
        '--logger-github',
        '--show-mutations=max',
        // Each mutant runs only the test cases that cover its line (PHPUnit --filter), not the whole test files.
        '--only-covering-test-cases',
        ...$scope,
    ];

    phpqa(['composer', 'exec', '--', 'infection', ...$options], [
        'XDEBUG_MODE' => 'coverage',
    ]);
}

/**
 * The options selecting what Infection mutates and the minimum it must reach; null while the tree holds none of the
 * files of section 9. A listed file that is missing once the tree is no longer empty is an error, never a silent skip.
 *
 * @return ?list<string>
 */
function infection_scope(bool $diff, bool $all, string $base, string $files): ?array
{
    if ($files !== '') {
        return ['--filter=' . $files, '--with-uncovered', '--min-msi=100', '--min-covered-msi=100'];
    }
    if ($diff) {
        // Infection runs "git diff <merge base> -- <source directories>" from the working directory and passes the
        // directories of infection.json.dist as they are written: this is why that file sits at the root of the
        // repository, not in .ci-tools with the other configurations. A diff that touches no source file is a success.
        return ['--git-diff-lines', '--git-diff-base=' . $base, '--min-msi=0', '--min-covered-msi=0'];
    }
    if ($all) {
        return ['--min-msi=0', '--min-covered-msi=0'];
    }
    $files = array_values(array_filter(INFECTION_STRICT_FILES, is_file(...)));
    if ($files === []) {
        return null;
    }
    if ($files !== INFECTION_STRICT_FILES) {
        io()->error(sprintf('Missing from the tree: %s.', implode(', ', array_diff(INFECTION_STRICT_FILES, $files))));
        exit(1);
    }

    return ['--filter=' . implode(',', $files), '--with-uncovered', '--min-msi=100', '--min-covered-msi=100'];
}

#[AsTask(description: 'Fix code style and apply Rector rules, then run static analysis')]
function prepare_pr(): void
{
    io()->title('Preparing code for pull request…');

    // The formatter runs last: Rector and the linter rewrite statements, the formatter lays them out.
    mago_lint_fix();
    rector_fix();
    mago_format_fix();

    io()->section('Running static analysis…');
    phpstan();
    deptrac();
    lint();
    composer_validate();

    io()->success('Code is ready. You may now commit your changes.');
}
