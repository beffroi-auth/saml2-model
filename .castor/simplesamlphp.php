<?php

declare(strict_types=1);

/*
 * The judge of section 9.5 of the specification, SimpleSAMLphp both ways, run by hand and never by the CI (section 12):
 * the library half, the installation half and the exchange of tests/Interop/simplesamlphp/, each in its containers,
 * from one task. tests/Interop/simplesamlphp/README.md holds what each step does, its results and its findings.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\context;
use function Castor\exit_code;
use function Castor\io;
use function Castor\run;

/**
 * The directory of the judge, relative to the root of the repository.
 */
const SIMPLESAMLPHP = 'tests/Interop/simplesamlphp';

/**
 * The library half runs on the PHP its README pins, whatever PHP_VERSION says.
 */
const SIMPLESAMLPHP_LIBRARY_IMAGE = 'ghcr.io/spomky-labs/phpqa:8.4';

#[AsTask(
    description: 'The judge of spec/model.md section 9.5, SimpleSAMLphp both ways: without an option, the whole exchange (install, up, the exchange, verify.php and xmlsec1 on what the model wrote, down); each option runs its step alone, in the order listed',
)]
function simplesamlphp(
    #[AsOption(
        description: 'The library half: simplesamlphp/saml2 writes its fixtures into tests/Fixture/real/ with the test keys',
    )]
    bool $produce = false,
    #[AsOption(
        description: 'Start the installation in the configuration of the exchange (SSP_EXCHANGE=true), the image built if needed',
    )]
    bool $up = false,
    #[AsOption(
        description: 'Play login and logout between the installation\'s two parties with curl and keep their documents in tests/Fixture/real/ (capture.sh, phase 1)',
    )]
    bool $capture = false,
    #[AsOption(
        description: 'Play the exchange with the model, the installation up: both ways, login and logout, and the probes',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'With the exchange: keep what SimpleSAMLphp sent in tests/Fixture/real/, dated, instead of received/',
    )]
    bool $keep = false,
    #[AsOption(
        description: 'The library half and xmlsec1 verify every signature of a batch: --in and --glob, the model\'s documents of the last exchange by default',
    )]
    bool $verify = false,
    #[AsOption(
        description: 'The batch of --verify: a directory, relative to the root, holding the signers\' metadata next to their documents',
    )]
    string $in = SIMPLESAMLPHP . '/written',
    #[AsOption(description: 'The files of --verify in that directory')]
    string $glob = '*.xml',
    #[AsOption(description: 'Stop the installation')]
    bool $down = false,
): void {
    if (! $produce && ! $up && ! $capture && ! $exchange && ! $verify && ! $down) {
        simplesamlphp_install();
        try {
            simplesamlphp_up();
            simplesamlphp_exchange($keep);
            simplesamlphp_verify($in, $glob);
        } finally {
            simplesamlphp_down();
        }

        return;
    }
    if ($produce) {
        simplesamlphp_install();
        simplesamlphp_library(['php', 'produce.php'], ['tests/Fixture/real' => '/out']);
    }
    if ($up) {
        simplesamlphp_install();
        simplesamlphp_up();
    }
    if ($capture) {
        run(['bash', SIMPLESAMLPHP . '/installation/capture.sh']);
    }
    if ($exchange) {
        simplesamlphp_exchange($keep);
    }
    if ($verify) {
        simplesamlphp_install();
        simplesamlphp_verify($in, $glob);
    }
    if ($down) {
        simplesamlphp_down();
    }
}

/**
 * What a clean checkout lacks: the package's dependencies, which the exchange loads, and the throwaway Composer
 * project of the library half.
 */
function simplesamlphp_install(): void
{
    if (! is_file('vendor/autoload.php')) {
        install();
    }
    if (! is_file(SIMPLESAMLPHP . '/library/vendor/autoload.php')) {
        simplesamlphp_library(['composer', 'install', '-n', '--no-progress']);
    }
}

/**
 * The installation in the configuration of the exchange: the identity provider publishes HTTP-POST next to
 * HTTP-Redirect; both parties read the model's metadata from written/, created here so that Docker does not.
 */
function simplesamlphp_up(): void
{
    if (! is_dir(SIMPLESAMLPHP . '/written')) {
        mkdir(SIMPLESAMLPHP . '/written');
    }
    run(
        [
            'docker',
            'compose',
            '-f',
            SIMPLESAMLPHP . '/installation/compose.yaml',
            'up',
            '-d',
            '--build',
            '--force-recreate',
        ],
        context: context()->withEnvironment(['SSP_EXCHANGE' => 'true']),
    );
    for ($attempt = 0; $attempt < 60; ++$attempt) {
        $idp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8081/simplesaml/module.php/saml/idp/metadata',
        ], context: context()->withQuiet());
        $sp = exit_code([
            'curl',
            '-fsS',
            '-o',
            '/dev/null',
            'http://127.0.0.1:8082/simplesaml/module.php/saml/sp/metadata/for-model',
        ], context: context()->withQuiet());
        if ($idp === 0 && $sp === 0) {
            return;
        }
        sleep(1);
    }
    io()->error('SimpleSAMLphp did not come up.');
    exit(1);
}

/**
 * The exchange script in the phpqa image, on the network of the installation, localhost:8081 and localhost:8082
 * pinned to its two containers so that every URL stays the one the installation knows.
 */
function simplesamlphp_exchange(bool $keep): void
{
    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '--network',
        'saml2-model-simplesamlphp_default',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'EXCHANGE_CONNECT_TO=localhost:8081:idp:80,localhost:8082:sp:80',
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', php_version()),
        'php',
        SIMPLESAMLPHP . '/exchange.php',
        ...($keep ? ['--keep'] : []),
    ]);
}

/**
 * verify.php of the library half, then xmlsec1, on every document of a batch that matches the glob.
 */
function simplesamlphp_verify(string $in, string $glob): void
{
    simplesamlphp_library(['php', 'verify.php', '/in', $glob], [$in => '/in:ro']);
    run([
        'docker',
        'run',
        '--rm',
        '-v',
        getcwd() . ':/project:ro',
        '-w',
        '/project',
        'alpine:3.22',
        'sh',
        '-c',
        'apk add -q xmlsec libxml2-utils && sh '
            . SIMPLESAMLPHP
            . '/xmlsec1-verify.sh '
            . escapeshellarg($in)
            . ' '
            . escapeshellarg($glob),
    ]);
}

function simplesamlphp_down(): void
{
    run(['docker', 'compose', '-f', SIMPLESAMLPHP . '/installation/compose.yaml', 'down']);
}

/**
 * A command of the library half in its container, library/ at /app and the test keys at /keys, as its README runs it.
 *
 * @param list<string> $command
 * @param array<string, string> $mounts directories relative to the root, and where the container sees them
 */
function simplesamlphp_library(array $command, array $mounts = []): void
{
    $volumes = [];
    foreach ($mounts as $directory => $path) {
        $volumes[] = '-v';
        $volumes[] = getcwd() . '/' . $directory . ':' . $path;
    }
    run([
        'docker',
        'run',
        '--rm',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '-e',
        'COMPOSER_HOME=/tmp/composer',
        '-v',
        getcwd() . '/' . SIMPLESAMLPHP . '/library:/app',
        '-v',
        getcwd() . '/tests/Fixture/keys:/keys:ro',
        ...$volumes,
        '-w',
        '/app',
        SIMPLESAMLPHP_LIBRARY_IMAGE,
        ...$command,
    ]);
}
