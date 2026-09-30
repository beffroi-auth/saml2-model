<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Response;

use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Assertion\Particle;
use Beffroi\Saml2\Model\Internal\Assertion\Structure;
use Beffroi\Saml2\Model\Protocol\Status;
use Beffroi\Saml2\Model\Protocol\StatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Xml\Core\Children;
use Beffroi\Xml\Core\Name;
use function count;
use Dom\Element;

/**
 * The structure of the envelope of a response, section 6.1 step 2, read before any key is touched: its children in
 * the order of the schema (M-5), saml:Issuer optional, ds:Signature optional, samlp:Extensions optional and never
 * read, samlp:Status, then the assertions; saml:EncryptedAssertion refused by name until sub-spike 9e (section 6.7);
 * exactly one saml:Assertion, a direct child, with a status of Success, none with another (M-4, M-13). What it keeps is
 * the status, and the one assertion of the element it read, never searched below it (I-11).
 *
 * @internal outside the compatibility promise of section 5
 */
final readonly class Envelope
{
    private function __construct(
        public Status $status,
        public ?Element $assertion,
    ) {
    }

    /**
     * @param Element $response a samlp:Response, as UnverifiedResponse::of() checked it
     *
     * @throws Unsupported when the response holds a saml:EncryptedAssertion (section 6.7)
     * @throws MalformedMessage when a child is out of order, repeated or not allowed, the status is malformed, or the
     *                          assertions are not what the status requires (M-4, M-5, M-13)
     */
    public static function of(Element $response): self
    {
        Structure::unsupported(
            $response,
            [Structure::saml('EncryptedAssertion')],
            'The response holds a saml:EncryptedAssertion, which the package does not support until sub-spike 9e (section 6.7).',
        );
        Structure::sequence(
            $response,
            [
                Particle::optional(Structure::saml('Issuer'), 'saml:Issuer'),
                Particle::optional(new Name(SignedResponse::DSIG, 'Signature'), 'ds:Signature'),
                Particle::optional(new Name(Saml::PROTOCOL, 'Extensions'), 'samlp:Extensions'),
                Particle::one(new Name(Saml::PROTOCOL, 'Status'), 'samlp:Status'),
                Particle::any([Structure::saml('Assertion')]),
            ],
            'samlp:Response',
        );
        $status = StatusReader::read(Children::one($response, new Name(Saml::PROTOCOL, 'Status')));
        $assertions = Children::named($response, Structure::saml('Assertion'));
        if ($status->code !== StatusCode::Success) {
            if ($assertions !== []) {
                throw new MalformedMessage('The samlp:Response has a status other than Success and holds a saml:Assertion (M-13).');
            }

            return new self($status, null);
        }
        if ($assertions === []) {
            throw new MalformedMessage('The samlp:Response has the status Success and holds no saml:Assertion (M-13).');
        }
        if (count($assertions) > 1) {
            throw new MalformedMessage('The samlp:Response holds more than one saml:Assertion (M-4).');
        }

        return new self($status, $assertions[0]);
    }
}
