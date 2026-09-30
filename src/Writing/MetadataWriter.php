<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Writing;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Internal\Writing\Tree;
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
use DateTimeImmutable;
use Dom\Element;
use InvalidArgumentException;

/**
 * An md:EntityDescriptor written in the order of section 6.6 (section 5.7): checked against what its reader refuses
 * or drops (M-15), built with DocumentFactory and one prefix per namespace, md and ds, the ID drawn by
 * SamlId::generate(), the validUntil in UTC to the second, each certificate the base64 of an X509Certificate, then
 * signed on request through Dsig's Signer with SamlLoader::create(), the Signature the first child of the root and
 * no InclusiveNamespaces prefix list (dsig.md section 6.2).
 */
final readonly class MetadataWriter
{
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
        $tree = Tree::of($document);
        $root = $document->root();
        $root->setAttribute('entityID', $descriptor->entityId);
        $root->setAttribute('ID', $id);
        if ($descriptor->validUntil instanceof DateTimeImmutable) {
            $root->setAttribute('validUntil', Time::write($descriptor->validUntil));
        }
        if ($descriptor->identityProvider instanceof IdentityProvider) {
            $this->identityProvider($tree, $root, $descriptor->identityProvider);
        }
        if ($descriptor->serviceProvider instanceof ServiceProvider) {
            $this->serviceProvider($tree, $root, $descriptor->serviceProvider);
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

    private function identityProvider(Tree $tree, Element $root, IdentityProvider $idp): void
    {
        $role = $tree->md($root, 'IDPSSODescriptor');
        $role->setAttribute('protocolSupportEnumeration', Saml::PROTOCOL);
        $role->setAttribute('WantAuthnRequestsSigned', $idp->wantAuthnRequestsSigned ? Boolean::TRUE : Boolean::FALSE);
        $this->keys($tree, $role, $idp->signingCertificates, $idp->encryptionCertificates);
        $this->endpoints($tree, $role, 'SingleLogoutService', $idp->singleLogoutServices);
        $this->formats($tree, $role, $idp->nameIdFormats);
        $this->endpoints($tree, $role, 'SingleSignOnService', $idp->singleSignOnServices);
    }

    private function serviceProvider(Tree $tree, Element $root, ServiceProvider $sp): void
    {
        $role = $tree->md($root, 'SPSSODescriptor');
        $role->setAttribute('protocolSupportEnumeration', Saml::PROTOCOL);
        $role->setAttribute('AuthnRequestsSigned', $sp->authnRequestsSigned ? Boolean::TRUE : Boolean::FALSE);
        $role->setAttribute('WantAssertionsSigned', $sp->wantAssertionsSigned ? Boolean::TRUE : Boolean::FALSE);
        $this->keys($tree, $role, $sp->signingCertificates, $sp->encryptionCertificates);
        $this->endpoints($tree, $role, 'SingleLogoutService', $sp->singleLogoutServices);
        $this->formats($tree, $role, $sp->nameIdFormats);
        foreach ($sp->assertionConsumerServices->endpoints as $endpoint) {
            $element = $tree->md($role, 'AssertionConsumerService');
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
    private function keys(Tree $tree, Element $role, array $signing, array $encryption): void
    {
        foreach ([
            ['signing',    $signing],
            ['encryption', $encryption],
        ] as [$use, $certificates]) {
            foreach ($certificates as $certificate) {
                $keyDescriptor = $tree->md($role, 'KeyDescriptor');
                $keyDescriptor->setAttribute('use', $use);
                $data = $tree->ds($tree->introduceDs($keyDescriptor, 'KeyInfo'), 'X509Data');
                $tree->ds($data, 'X509Certificate')->append($certificate);
            }
        }
    }

    /**
     * @param list<Endpoint> $endpoints
     */
    private function endpoints(Tree $tree, Element $role, string $local, array $endpoints): void
    {
        foreach ($endpoints as $endpoint) {
            $element = $tree->md($role, $local);
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
    private function formats(Tree $tree, Element $role, array $formats): void
    {
        foreach ($formats as $format) {
            $tree->md($role, 'NameIDFormat')->append($format->value);
        }
    }
}
