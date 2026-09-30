<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use DateTimeImmutable;
use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Metadata\Binding;
use Beffroi\Saml2\Model\Metadata\Endpoint;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\SamlLoader;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Saml2\Model\Value\SamlId;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Document;
use Beffroi\Xml\Core\DocumentFactory;
use Beffroi\Xml\Core\Exception\RefusedXml;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\SigningFailed;
use Beffroi\Xml\Dsig\Signer;
use Dom\Element;
use InvalidArgumentException;
use LogicException;

/**
 * An md:EntityDescriptor written in the order of section 6.6 (section 5.7): checked against what its reader refuses
 * or drops (M-15), built with DocumentFactory and one prefix per namespace, md and ds, the ID drawn by
 * SamlId::generate(), the validUntil in UTC to the second, each certificate the base64 of an X509Certificate, then
 * signed on request through Dsig's Signer with SamlLoader::create(), the Signature the first child of the root and
 * no InclusiveNamespaces prefix list (dsig.md section 6.2).
 */
final readonly class MetadataWriter
{
    private const string XMLNS = 'http://www.w3.org/2000/xmlns/';

    private const string DSIG = 'http://www.w3.org/2000/09/xmldsig#';

    /**
     * @throws InvalidArgumentException when the descriptor holds no role, its identity provider no single sign-on
     *                                   service, its service provider no assertion consumer service or one that is
     *                                   not on HTTP-POST: a programming error of the caller (section 5.8)
     * @throws RefusedXml what Core's serializer and loader and Dsig refuse while signing
     * @throws SigningFailed when the signing key fails
     */
    public function write(EntityDescriptor $descriptor, ?Signing $signing): Document
    {
        $this->check($descriptor);
        $id = SamlId::generate();
        $document = new DocumentFactory()->create(new Name(Saml::METADATA, 'EntityDescriptor'), 'md');
        $root = $document->root();
        $root->setAttribute('entityID', $descriptor->entityId);
        $root->setAttribute('ID', $id);
        if ($descriptor->validUntil instanceof DateTimeImmutable) {
            $root->setAttribute('validUntil', Time::write($descriptor->validUntil));
        }
        if ($descriptor->identityProvider instanceof IdentityProvider) {
            $this->identityProvider($root, $descriptor->identityProvider);
        }
        if ($descriptor->serviceProvider instanceof ServiceProvider) {
            $this->serviceProvider($root, $descriptor->serviceProvider);
        }
        if (! $signing instanceof Signing) {
            return $document;
        }

        return new Signer(SamlLoader::create())->sign(
            $document,
            $id,
            $signing->key,
            $signing->algorithm,
            certificatePem: $signing->certificatePem,
        );
    }

    /**
     * Section 6.6 step 1: what the reader would refuse or drop is never written (M-15).
     *
     * @throws InvalidArgumentException
     */
    private function check(EntityDescriptor $descriptor): void
    {
        if (
            ! $descriptor->identityProvider instanceof IdentityProvider
            && ! $descriptor->serviceProvider instanceof ServiceProvider
        ) {
            throw new InvalidArgumentException('The entity descriptor holds no role to write (section 6.6).');
        }
        if ($descriptor->identityProvider?->singleSignOnServices === []) {
            throw new InvalidArgumentException('The identity provider holds no single sign-on service, which its reader requires (section 6.6).');
        }
        $assertionConsumers = $descriptor->serviceProvider->assertionConsumerServices->endpoints ?? null;
        if ($assertionConsumers === []) {
            throw new InvalidArgumentException('The service provider holds no assertion consumer service, which its reader requires (section 6.6).');
        }
        foreach ($assertionConsumers ?? [] as $assertionConsumer) {
            if ($assertionConsumer->binding !== Binding::HttpPost) {
                throw new InvalidArgumentException('An assertion consumer service is not on HTTP-POST, which its reader drops (section 6.6).');
            }
        }
    }

    private function identityProvider(Element $root, IdentityProvider $idp): void
    {
        $role = $this->md($root, 'IDPSSODescriptor');
        $role->setAttribute('protocolSupportEnumeration', Saml::PROTOCOL);
        $role->setAttribute('WantAuthnRequestsSigned', $idp->wantAuthnRequestsSigned ? Boolean::TRUE : Boolean::FALSE);
        $this->keys($role, $idp->signingCertificates, $idp->encryptionCertificates);
        $this->endpoints($role, 'SingleLogoutService', $idp->singleLogoutServices);
        $this->formats($role, $idp->nameIdFormats);
        $this->endpoints($role, 'SingleSignOnService', $idp->singleSignOnServices);
    }

    private function serviceProvider(Element $root, ServiceProvider $sp): void
    {
        $role = $this->md($root, 'SPSSODescriptor');
        $role->setAttribute('protocolSupportEnumeration', Saml::PROTOCOL);
        $role->setAttribute('AuthnRequestsSigned', $sp->authnRequestsSigned ? Boolean::TRUE : Boolean::FALSE);
        $role->setAttribute('WantAssertionsSigned', $sp->wantAssertionsSigned ? Boolean::TRUE : Boolean::FALSE);
        $this->keys($role, $sp->signingCertificates, $sp->encryptionCertificates);
        $this->endpoints($role, 'SingleLogoutService', $sp->singleLogoutServices);
        $this->formats($role, $sp->nameIdFormats);
        foreach ($sp->assertionConsumerServices->endpoints as $endpoint) {
            $element = $this->md($role, 'AssertionConsumerService');
            $element->setAttribute('Binding', $endpoint->binding->value);
            $element->setAttribute('Location', $endpoint->location);
            $element->setAttribute('index', (string) $endpoint->index);
            if ($endpoint->isDefault !== null) {
                $element->setAttribute('isDefault', $endpoint->isDefault ? Boolean::TRUE : Boolean::FALSE);
            }
        }
    }

    /**
     * One md:KeyDescriptor per certificate, those for signing first, each ds:KeyInfo declaring the ds prefix it
     * introduces (core.md section 6.5).
     *
     * @param list<string> $signing
     * @param list<string> $encryption
     */
    private function keys(Element $role, array $signing, array $encryption): void
    {
        foreach ([
            ['signing',    $signing],
            ['encryption', $encryption],
        ] as [$use, $certificates]) {
            foreach ($certificates as $certificate) {
                $keyDescriptor = $this->md($role, 'KeyDescriptor');
                $keyDescriptor->setAttribute('use', $use);
                $keyInfo = $this->child($keyDescriptor, self::DSIG, 'ds:KeyInfo');
                $keyInfo->setAttributeNS(self::XMLNS, 'xmlns:ds', self::DSIG);
                $data = $this->child($keyInfo, self::DSIG, 'ds:X509Data');
                $this->child($data, self::DSIG, 'ds:X509Certificate')->append($certificate);
            }
        }
    }

    /**
     * @param list<Endpoint> $endpoints
     */
    private function endpoints(Element $role, string $local, array $endpoints): void
    {
        foreach ($endpoints as $endpoint) {
            $element = $this->md($role, $local);
            $element->setAttribute('Binding', $endpoint->binding->value);
            $element->setAttribute('Location', $endpoint->location);
            if ($endpoint->responseLocation !== null) {
                $element->setAttribute('ResponseLocation', $endpoint->responseLocation);
            }
        }
    }

    /**
     * @param list<NameIdFormat> $formats
     */
    private function formats(Element $role, array $formats): void
    {
        foreach ($formats as $format) {
            $this->md($role, 'NameIDFormat')->append($format->value);
        }
    }

    private function md(Element $parent, string $local): Element
    {
        return $this->child($parent, Saml::METADATA, 'md:' . $local);
    }

    /**
     * A prefixed element appended to its parent (core.md section 6.5).
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
