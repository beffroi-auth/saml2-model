<?php

declare(strict_types=1);

/*
 * The figure of section 9.6 of spec/model.md, measured on SimpleSAMLphp's real responses: how long the model takes to
 * validate one, from the bytes loaded by SamlLoader and UnverifiedResponse::of() to AcceptedAssertion, a new replay
 * store each time, the clock frozen at its IssueInstant. Each response is validated 20 times to warm up, then 500
 * times; the median and the 95th percentile are printed in milliseconds.
 *
 * From the root of the repository, on each PHP of the CI:
 *   docker run --rm -v "$PWD:/project:ro" -w /project ghcr.io/spomky-labs/phpqa:8.5 php tests/Interop/simplesamlphp/timing.php
 */

use Beffroi\Saml2\Model\Metadata\MetadataReader;
use Beffroi\Saml2\Model\Protocol\UnverifiedResponse;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Tests\Support\FrozenClock;
use Beffroi\Saml2\Model\Tests\Support\InMemoryReplayGuard;
use Beffroi\Saml2\Model\Validation\ExpectedResponse;
use Beffroi\Saml2\Model\Validation\ResponseValidator;

require __DIR__ . '/../../../vendor/autoload.php';

$real = __DIR__ . '/../../Fixture/real/';
$acs = 'http://localhost:8082/simplesaml/module.php/saml/sp/saml2-acs.php/default-sp';
$sp = 'http://localhost:8082/simplesaml/module.php/saml/sp/metadata/default-sp';
$cases = [
    'the assertion signed' => [
        'simplesamlphp-2.5.3.1-idp-response-signed-assertion-2026-09-30.xml',
        '2026-09-30T10:34:41Z',
        '_7cc71f776e69f4f4cdb3fba9ebc8392b9491d4e6e4',
    ],
    'the response and the assertion signed' => [
        'simplesamlphp-2.5.3.1-idp-response-signed-both-2026-09-30.xml',
        '2026-09-30T10:34:38Z',
        '_8a3c5b08ae40d362750a2b17db4f78d18bdd9b369e',
    ],
];

printf("PHP %s, OpenSSL %s\n", PHP_VERSION, OPENSSL_VERSION_TEXT);
foreach ($cases as $name => [$file, $issueInstant, $requestId]) {
    $clock = new FrozenClock(new DateTimeImmutable($issueInstant));
    $idp = new MetadataReader(SamlLoader::create(), $clock)
        ->readTrusted(SamlLoader::create()->load((string) file_get_contents($real . 'simplesamlphp-2.5.3.1-idp-metadata-2026-09-30.xml')))
        ->identityProvider ?? throw new LogicException('an identity provider');
    $bytes = (string) file_get_contents($real . $file);
    $expected = ExpectedResponse::toRequest($requestId, $acs, $sp);
    $durations = [];
    foreach (range(1, 520) as $run) {
        $start = hrtime(true);
        $loader = SamlLoader::create();
        new ResponseValidator($loader, $clock, new InMemoryReplayGuard())
            ->validate(UnverifiedResponse::of($loader->load($bytes)), $idp, $expected);
        if ($run > 20) {
            $durations[] = (hrtime(true) - $start) / 1e6;
        }
    }
    sort($durations);
    printf(
        "%s: median %.2f ms, 95th percentile %.2f ms, over %d runs\n",
        $name,
        $durations[intdiv(count($durations), 2)],
        $durations[(int) floor(count($durations) * 0.95)],
        count($durations),
    );
}
