<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Protocol\LogoutRequest;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use DateTimeImmutable;
use Dom\Element;
use LogicException;

/**
 * A samlp:LogoutRequest written in the order of section 6.6 (section 5.7): what its reader would refuse, its
 * constructor refused already (M-15); built with DocumentFactory and one prefix per namespace, samlp and saml, both
 * declared on the root, the ID the request carries, the times in UTC to the second, the Format of the NameID always
 * written; then signed on request through Dsig's Signer with SamlLoader::create(), the Signature after the Issuer
 * (SAML Core §3.2.1) and no InclusiveNamespaces prefix list. Signed for HTTP-POST, unsigned for HTTP-Redirect, whose
 * binding signs the query string (section 6.8).
 */
final readonly class LogoutRequestWriter
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    /**
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function write(LogoutRequest $request, ?Signing $signing): Document
    {
        $document = new DocumentFactory()->create(new Name(Saml::PROTOCOL, 'LogoutRequest'), 'samlp');
        $root = $document->root();
        $root->setAttributeNS(self::XMLNS, 'xmlns:saml', Saml::ASSERTION);
        $root->setAttribute('ID', $request->id);
        $root->setAttribute('Version', Saml::VERSION);
        $root->setAttribute('IssueInstant', Time::write($request->issueInstant));
        $root->setAttribute('Destination', $request->destination);
        if ($request->notOnOrAfter instanceof DateTimeImmutable) {
            $root->setAttribute('NotOnOrAfter', Time::write($request->notOnOrAfter));
        }
        if ($request->reason !== null) {
            $root->setAttribute('Reason', $request->reason);
        }
        $this->child($root, Saml::ASSERTION, 'saml:Issuer')->append($request->issuer->entityId);
        $nameId = $this->child($root, Saml::ASSERTION, 'saml:NameID');
        $nameId->setAttribute('Format', $request->nameId->format->value);
        foreach ([
            'NameQualifier' => $request->nameId->nameQualifier,
            'SPNameQualifier' => $request->nameId->spNameQualifier,
            'SPProvidedID' => $request->nameId->spProvidedId,
        ] as $attribute => $value) {
            if ($value === null) {
                continue;
            }
            $nameId->setAttribute($attribute, $value);
        }
        $nameId->append($request->nameId->value);
        foreach ($request->sessionIndexes as $sessionIndex) {
            $this->child($root, Saml::PROTOCOL, 'samlp:SessionIndex')->append($sessionIndex);
        }
        if (! $signing instanceof Signing) {
            return $document;
        }

        return new Signer(SamlLoader::create())->sign(
            $document,
            $request->id,
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
