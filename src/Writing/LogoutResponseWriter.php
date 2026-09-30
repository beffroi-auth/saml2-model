<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Protocol\LogoutResponse;
use Beffroi\Saml2\Model\Protocol\SecondLevelStatusCode;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use Dom\Element;
use LogicException;

/**
 * A samlp:LogoutResponse written in the order of section 6.6 (section 5.7): what its reader would refuse, its
 * constructor refused already (M-15); built with DocumentFactory and one prefix per namespace, samlp and saml, both
 * declared on the root, the ID the response carries, the InResponseTo of the request it answers, the IssueInstant in
 * UTC to the second, the status with its second-level code when it has one; then signed on request through Dsig's
 * Signer with SamlLoader::create(), the Signature after the Issuer (SAML Core §3.2.1) and no InclusiveNamespaces
 * prefix list. Signed for HTTP-POST, unsigned for HTTP-Redirect, whose binding signs the query string (section 6.8).
 */
final readonly class LogoutResponseWriter
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function write(LogoutResponse $response, ?Signing $signing): Document
    {
        $document = new DocumentFactory()->create(new Name(Saml::PROTOCOL, 'LogoutResponse'), 'samlp');
        $root = $document->root();
        $root->setAttributeNS(self::XMLNS, 'xmlns:saml', Saml::ASSERTION);
        $root->setAttribute('ID', $response->id);
        $root->setAttribute('Version', Saml::VERSION);
        $root->setAttribute('IssueInstant', Time::write($response->issueInstant));
        $root->setAttribute('Destination', $response->destination);
        $root->setAttribute('InResponseTo', $response->inResponseTo);
        $this->child($root, Saml::ASSERTION, 'saml:Issuer')->append($response->issuer->entityId);
        $code = $this->child($this->child($root, Saml::PROTOCOL, 'samlp:Status'), Saml::PROTOCOL, 'samlp:StatusCode');
        $code->setAttribute('Value', $response->status->code->value);
        if ($response->status->secondLevel instanceof SecondLevelStatusCode) {
            $this->child($code, Saml::PROTOCOL, 'samlp:StatusCode')->setAttribute(
                'Value',
                $response->status->secondLevel->value,
            );
        }
        if (! $signing instanceof Signing) {
            return $document;
        }

        return new Signer(SamlLoader::create())->sign(
            $document,
            $response->id,
            $signing->key,
            $signing->algorithm,
            after: new Name(Saml::ASSERTION, 'Issuer'),
            certificatePem: $signing->certificatePem,
        );
    }

    /**
     * A prefixed element appended to its parent, its prefix declared on the root (core.md section 6.5).
     */
    private function child(Element $parent, string $namespace, string $qualifiedName): Element
    {
        $document =
            $parent->ownerDocument ?? throw new LogicException('An element of a built document belongs to it (section 6.6).');
        $child = $document->createElementNS($namespace, $qualifiedName);
        $parent->appendChild($child);

        return $child;
    }
}
