<?php

declare(strict_types=1);

/*
 * Reads every document of a directory with simplesamlphp/saml2, as SimpleSAMLphp reads what a peer sends, and
 * validates every signature under the test certificates of tests/Fixture/keys/ (spec/model.md section 9.5.1).
 *
 *   php verify.php <directory> [<glob>]     the glob defaults to *.xml
 *
 * The keys come from the metadata of the batch, never from a message (M-3): every md:EntityDescriptor of the batch
 * is read first, each of its certificates must be one of the test certificates, and a signed one is verified under
 * its own; each message is then verified under the signing certificates of the metadata of its Issuer. Every
 * ds:Signature a message or an assertion carries as a direct child must validate, through the object's own
 * validate(), the call SimpleSAMLphp makes (modules/saml/src/Message.php); a message that carries none fails,
 * metadata without one passes. One line per file, OK or FAIL and why; the exit status is 1 when any file fails.
 *
 * Run from the root of the repository (tests/Interop/simplesamlphp/README.md):
 *   docker run --rm -v "$PWD/tests/Interop/simplesamlphp/library:/app" -v "$PWD/tests/Fixture/keys:/keys:ro" \
 *       -v "$PWD/tests/Fixture/real:/in:ro" -w /app ghcr.io/spomky-labs/phpqa:8.4 \
 *       php verify.php /in 'simplesamlphp-saml2-4.20.3-*.xml'
 */

require '/app/vendor/autoload.php';

use RobRichards\XMLSecLibs\XMLSecurityKey;
use SAML2\Assertion;
use SAML2\Compat\ContainerSingleton;
use SAML2\Compat\MockContainer;
use SAML2\Constants;
use SAML2\DOMDocumentFactory;
use SAML2\Message;
use SAML2\Response;
use SAML2\Utils;
use SAML2\XML\ds\X509Data;
use SAML2\XML\md\EntityDescriptor;

const NS_DS = 'http://www.w3.org/2000/09/xmldsig#';

ContainerSingleton::setContainer(new MockContainer());

if ($argc < 2 || !is_dir($argv[1])) {
    fwrite(STDERR, "usage: php verify.php <directory> [<glob>]\n");
    exit(2);
}
$files = glob(rtrim($argv[1], '/') . '/' . ($argv[2] ?? '*.xml')) ?: [];
sort($files);
if ($files === []) {
    fwrite(STDERR, "no document matches in {$argv[1]}\n");
    exit(2);
}

/** @var array<string, string> $testCertificates the base64 of each test certificate => the file it comes from */
$testCertificates = [];
foreach (glob('/keys/*-certificate.pem') ?: [] as $pem) {
    $testCertificates[base64Of((string) file_get_contents($pem))] = basename($pem);
}
if ($testCertificates === []) {
    fwrite(STDERR, "no test certificate in /keys\n");
    exit(2);
}

/** @var array<string, string> $bytes */
$bytes = [];
foreach ($files as $file) {
    $bytes[$file] = (string) file_get_contents($file);
}

/** @var array<string, list<string>> $keysByEntity entity ID => the base64 of its signing certificates */
$keysByEntity = [];
$results = [];
foreach ($bytes as $file => $document) {
    if (isMetadata($document)) {
        $results[$file] = attempt(static function () use ($document, $testCertificates, &$keysByEntity): string {
            return readMetadata($document, $testCertificates, $keysByEntity);
        });
    }
}
foreach ($bytes as $file => $document) {
    $results[$file] ??= attempt(static function () use ($document, $keysByEntity, $testCertificates): string {
        return readMessage($document, $keysByEntity, $testCertificates);
    });
}

$failed = 0;
foreach ($files as $file) {
    [$ok, $detail] = $results[$file];
    $failed += $ok ? 0 : 1;
    printf("%-4s %s: %s\n", $ok ? 'OK' : 'FAIL', basename($file), $detail);
}
printf("%d documents, %d failed\n", count($files), $failed);
exit($failed === 0 ? 0 : 1);

/**
 * @param array<string, string>        $testCertificates
 * @param array<string, list<string>> $keysByEntity
 */
function readMetadata(string $document, array $testCertificates, array &$keysByEntity): string
{
    $root = load($document);
    $signed = signatureOf($root) !== null;
    try {
        $descriptor = new EntityDescriptor($root);
    } catch (Throwable $e) {
        throw new RuntimeException('the library refuses to read it: ' . $e->getMessage(), 0, $e);
    }
    $signing = [];
    $labels = [];
    foreach ($descriptor->getRoleDescriptor() as $role) {
        foreach ($role->getKeyDescriptor() as $keyDescriptor) {
            foreach ($keyDescriptor->getKeyInfo()?->getInfo() ?? [] as $info) {
                if (!$info instanceof X509Data) {
                    continue;
                }
                foreach ($info->getData() as $data) {
                    if (!$data instanceof SAML2\XML\ds\X509Certificate) {
                        continue;
                    }
                    $base64 = base64Of($data->getCertificate());
                    if (!isset($testCertificates[$base64])) {
                        throw new RuntimeException('a KeyDescriptor carries a certificate that is not a test certificate');
                    }
                    $labels[$testCertificates[$base64]] = true;
                    if (in_array($keyDescriptor->getUse(), [null, 'signing'], true)) {
                        $signing[] = $base64;
                    }
                }
            }
        }
    }
    if ($signing === []) {
        throw new RuntimeException('no signing certificate');
    }
    $what = 'metadata of ' . $descriptor->getEntityID() . ', certificates ' . implode(', ', array_keys($labels));
    if ($signed) {
        $what .= ', signature valid under ' . validate($descriptor, static fn (): DOMElement => load($document), $signing, $testCertificates);
    } else {
        $what .= ', unsigned';
    }
    $keysByEntity[$descriptor->getEntityID()] = array_values(array_unique([...($keysByEntity[$descriptor->getEntityID()] ?? []), ...$signing]));

    return $what;
}

/**
 * @param array<string, list<string>> $keysByEntity
 * @param array<string, string>       $testCertificates
 */
function readMessage(string $document, array $keysByEntity, array $testCertificates): string
{
    $root = load($document);
    $rootSigned = signatureOf($root) !== null;
    $assertionsSigned = array_map(
        static fn (DOMElement $assertion): bool => signatureOf($assertion) !== null,
        directChildren($root, Constants::NS_SAML, 'Assertion'),
    );
    if (directChildren($root, Constants::NS_SAML, 'EncryptedAssertion') !== []) {
        throw new RuntimeException('an EncryptedAssertion, which this script does not decrypt');
    }
    try {
        $message = Message::fromXML($root);
    } catch (Throwable $e) {
        throw new RuntimeException('the library refuses to read it: ' . $e->getMessage(), 0, $e);
    }
    $checked = [];
    if ($rootSigned) {
        $keys = keysOf(issuerOf($message), $keysByEntity);
        $pristine = static fn (): DOMElement => load($document);
        $checked[] = $root->localName . ' signature valid under ' . validate($message, $pristine, $keys, $testCertificates);
    }
    if ($message instanceof Response) {
        foreach ($message->getAssertions() as $index => $assertion) {
            if (!$assertion instanceof Assertion) {
                continue;
            }
            if (!$assertionsSigned[$index]) {
                $checked[] = 'assertion unsigned';
                continue;
            }
            $keys = keysOf($assertion->getIssuer()->getValue(), $keysByEntity);
            $pristine = static fn (): DOMElement => directChildren(load($document), Constants::NS_SAML, 'Assertion')[$index];
            $checked[] = 'assertion signature valid under ' . validate($assertion, $pristine, $keys, $testCertificates);
        }
    }
    if (!$rootSigned && !in_array(true, $assertionsSigned, true)) {
        throw new RuntimeException('no signature: nothing in the ' . $root->localName . ' is signed');
    }

    return $root->localName . ' from ' . issuerOf($message) . ', ' . implode(', ', $checked);
}

/**
 * The object's own validate(), under each signing certificate of the issuer's metadata: true under one of them is a
 * valid signature. validate() returns false when the library set the signature aside while reading the document,
 * as it does for a digest that does not match; the reason is then asked of Utils::validateElement(), on a copy loaded
 * again, since xmlseclibs removes the ds:Signature it checked from the tree it was given.
 *
 * @param list<string>          $keys
 * @param array<string, string> $testCertificates
 */
function validate(Message|Assertion|EntityDescriptor $object, Closure $pristine, array $keys, array $testCertificates): string
{
    $errors = [];
    foreach ($keys as $base64) {
        $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'public']);
        $key->loadKey("-----BEGIN CERTIFICATE-----\n" . chunk_split($base64, 64, "\n") . "-----END CERTIFICATE-----\n", false, true);
        try {
            if ($object->validate($key) === true) {
                return $testCertificates[$base64];
            }
            try {
                Utils::validateElement($pristine());
                $errors[] = 'the library found no signature to validate';
            } catch (Throwable $e) {
                $errors[] = $e->getMessage();
            }
        } catch (Throwable $e) {
            $errors[] = $e->getMessage();
        }
    }

    throw new RuntimeException('signature not valid: ' . implode('; ', array_unique($errors)));
}

function isMetadata(string $document): bool
{
    try {
        $root = load($document);
    } catch (Throwable) {
        return false;
    }

    return $root->namespaceURI === Constants::NS_MD && $root->localName === 'EntityDescriptor';
}

function load(string $document): DOMElement
{
    return DOMDocumentFactory::fromString($document)->documentElement;
}

function issuerOf(Message $message): string
{
    $issuer = $message->getIssuer()?->getValue();
    if ($issuer === null && $message instanceof Response && $message->getAssertions() !== []) {
        $assertion = $message->getAssertions()[0];
        $issuer = $assertion instanceof Assertion ? $assertion->getIssuer()->getValue() : null;
    }
    if ($issuer === null) {
        throw new RuntimeException('no Issuer to choose the metadata by');
    }

    return $issuer;
}

/**
 * @param array<string, list<string>> $keysByEntity
 *
 * @return list<string>
 */
function keysOf(string $issuer, array $keysByEntity): array
{
    return $keysByEntity[$issuer] ?? throw new RuntimeException('no valid metadata in the batch for the issuer ' . $issuer);
}

function signatureOf(DOMElement $element): ?DOMElement
{
    return directChildren($element, NS_DS, 'Signature')[0] ?? null;
}

/**
 * @return list<DOMElement>
 */
function directChildren(DOMElement $element, string $namespace, string $localName): array
{
    $children = [];
    foreach ($element->childNodes as $child) {
        if ($child instanceof DOMElement && $child->namespaceURI === $namespace && $child->localName === $localName) {
            $children[] = $child;
        }
    }

    return $children;
}

function base64Of(string $certificate): string
{
    return (string) preg_replace('/-----[A-Z ]+-----|\s+/', '', $certificate);
}

/**
 * @return array{bool, string}
 */
function attempt(Closure $check): array
{
    try {
        return [true, $check()];
    } catch (Throwable $e) {
        return [false, $e->getMessage()];
    }
}
