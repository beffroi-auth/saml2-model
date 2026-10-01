<?php

declare(strict_types=1);

/*
 * Keycloak, the second target of the judge of section 9.5 (story #14): run by hand, never in the CI and never a
 * dependency of the package. Every command, setting and result is in tests/Interop/keycloak/README.md.
 */

use Castor\Attribute\AsOption;
use Castor\Attribute\AsTask;
use function Castor\capture;
use function Castor\context;
use function Castor\io;
use function Castor\run;

const KEYCLOAK_COMPOSE = 'tests/Interop/keycloak/compose.yaml';

/**
 * Where the documents of a run go unless --output says otherwise, ignored by git with the rest of tmp-phpqa/: the
 * model's in its model/ directory, for xmlsec1.
 */
const KEYCLOAK_RUN = 'tmp-phpqa/keycloak';

#[AsTask(
    description: 'Keycloak against the model, both ways (spec/model.md section 9.5, tests/Interop/keycloak/README.md): without an option, up, capture, exchange, verify and down, in that order',
)]
function keycloak(
    #[AsOption(description: 'Start Keycloak, the realms of tests/Interop/keycloak/realms/ imported with new keys')]
    bool $up = false,
    #[AsOption(description: 'Capture a login and a logout of the broker of realm sp against realm idp (capture.sh)')]
    bool $capture = false,
    #[AsOption(
        description: 'Configure Keycloak from the model\'s metadata and play the model as identity provider and as service provider (exchange.php)',
    )]
    bool $exchange = false,
    #[AsOption(
        description: 'Verify with xmlsec1 every document the model wrote in the exchange, and every signature of Keycloak\'s documents in --output',
    )]
    bool $verify = false,
    #[AsOption(description: 'Stop Keycloak and remove its container, its realms and keys with it')]
    bool $down = false,
    #[AsOption(
        description: 'Where Keycloak\'s documents are written, dated: tests/Fixture/real to renew the fixtures, whose files of the same day it rewrites',
    )]
    string $output = KEYCLOAK_RUN,
): void {
    if (! $up && ! $capture && ! $exchange && ! $verify && ! $down) {
        [$up, $capture, $exchange, $verify, $down] = [true, true, true, true, true];
    }
    $model = KEYCLOAK_RUN . '/model';
    if ($up) {
        run(['docker', 'compose', '-f', KEYCLOAK_COMPOSE, 'up', '-d']);
    }

    try {
        if ($capture || $exchange) {
            // A run leaves only its own documents behind in the ignored directories, never touching the fixtures.
            $stale = glob($model . '/*') ?: [];
            if ($output === KEYCLOAK_RUN || str_starts_with($output, KEYCLOAK_RUN . '/')) {
                $stale = [...$stale, ...(glob($output . '/keycloak-*.xml') ?: [])];
            }
            foreach ($stale as $file) {
                unlink($file);
            }
        }
        if ($capture) {
            io()->section('Capture: the broker of realm sp against realm idp');
            run(['bash', 'tests/Interop/keycloak/capture.sh', $output]);
        }
        if ($exchange) {
            io()->section('Exchange: the model against Keycloak, both ways');
            keycloak_exchange($output, $model);
        }
        if ($verify) {
            io()->section('xmlsec1: the documents the model wrote');
            $identityProvider = glob($model . '/model-idp-*.xml') ?: [];
            $serviceProvider = glob($model . '/model-sp-*.xml') ?: [];
            if ($identityProvider === [] || $serviceProvider === []) {
                io()->error('No document of the model in ' . $model . ': run the exchange first.');
                exit(1);
            }
            xmlsec1($identityProvider, 'tests/Fixture/keys/idp-signing-certificate.pem');
            xmlsec1($serviceProvider, 'tests/Fixture/keys/sp-signing-certificate.pem');
            io()->section('xmlsec1: the signatures of Keycloak\'s documents in ' . $output);
            run([
                'docker',
                'run',
                '--rm',
                '-i',
                '-v',
                getcwd() . ':/project:ro',
                '-w',
                '/project',
                'alpine:3.22',
                'sh',
                '-c',
                'apk add -q xmlsec libxml2-utils openssl >/dev/null 2>&1 && xmlsec1 --version && sh tests/Interop/keycloak/verify.sh '
                    . escapeshellarg($output),
            ]);
        }
    } finally {
        if ($down) {
            run(['docker', 'compose', '-f', KEYCLOAK_COMPOSE, 'down']);
        }
    }
}

/**
 * Runs exchange.php in the phpqa image, inside the network namespace of the Keycloak container: localhost:8180 is
 * Keycloak there, the host and the port of every URL Keycloak builds and checks.
 */
function keycloak_exchange(string $output, string $model): void
{
    $container = trim(capture(
        ['docker', 'compose', '-f', KEYCLOAK_COMPOSE, 'ps', '-q', 'keycloak'],
        context()->withQuiet()->withAllowFailure(),
        onFailure: '',
    ));
    if ($container === '') {
        io()->error('Keycloak is not running: castor keycloak --up.');
        exit(1);
    }

    run([
        'docker',
        'run',
        '--rm',
        '--init',
        '-i',
        '--user',
        sprintf('%s:%s', getmyuid(), getmygid()),
        '--network',
        'container:' . $container,
        '-v',
        getcwd() . ':/project',
        '-w',
        '/project',
        '-e',
        'XDEBUG_MODE=off',
        sprintf('ghcr.io/spomky-labs/phpqa:%s', php_version()),
        'php',
        'tests/Interop/keycloak/exchange.php',
        $output,
        $model,
    ]);
}
