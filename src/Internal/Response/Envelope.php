<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Protocol\StatusReader;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use function count;
use Dom\Element;

/**
 * Section 6.1 step 2
 *
 * Read before any key is touched, so that a response refused here costs no operation of a key.
 *
 * @internal
 */
final readonly class Envelope
{
    private function __construct(
        public Status $status,
        public ?Element $assertion,
        public bool $encrypted,
    ) {
    }

    /**
     * @throws Unsupported
     * @throws MalformedMessage
     */
    public static function of(Element $response): self
    {
        [$issuer, , , [$element], $assertions] = Schema::children($response, 'samlp:Response', [
            Particle::of(Schema::saml('Issuer'), 0, 1),
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::samlp('Extensions'), 0, 1),
            Particle::of(Schema::samlp('Status'), 1, 1),
            new Particle(
                'saml:Assertion or saml:EncryptedAssertion',
                [Schema::saml('Assertion'), Schema::saml('EncryptedAssertion')],
                0,
                Particle::UNBOUNDED,
            ),
        ]);
        StatusReader::structure($element);
        $status = StatusReader::read($element);
        if ($status->code !== StatusCode::Success) {
            if ($assertions !== []) {
                throw new MalformedMessage('The samlp:Response has a status other than Success and holds a saml:Assertion or a saml:EncryptedAssertion (M-13).');
            }

            return new self($status, null, false);
        }
        if ($assertions === []) {
            throw new MalformedMessage('The samlp:Response has the status Success and holds no saml:Assertion or saml:EncryptedAssertion (M-13).');
        }
        if (count($assertions) > 1) {
            throw new MalformedMessage('The samlp:Response holds more than one saml:Assertion or saml:EncryptedAssertion (M-4).');
        }
        $encrypted = Schema::saml('EncryptedAssertion')->matches($assertions[0]);
        if ($encrypted) {
            Schema::unsupported(
                $assertions[0],
                [Schema::xenc('EncryptedKey')],
                'The saml:EncryptedAssertion holds an xenc:EncryptedKey next to its xenc:EncryptedData, a form the package does not support (section 6.7).',
            );
            Schema::children($assertions[0], 'saml:EncryptedAssertion', [
                Particle::of(Schema::xenc('EncryptedData'), 1, 1),
            ]);
            if ($issuer === []) {
                throw new MalformedMessage('The response holds a saml:EncryptedAssertion and has no saml:Issuer (M-8).');
            }
        }

        return new self($status, $assertions[0], $encrypted);
    }
}
