<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Metadata;

use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\EntityDescriptor;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Saml2\Model\Value\Uri;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use function count;
use DateTimeImmutable;
use Dom\Element;

/**
 * Section 6.5
 *
 * @internal
 */
final readonly class EntityDescriptorReader
{
    /**
     * Section 6.5 steps 1 and 2
     *
     * @throws Unsupported
     * @throws MalformedMessage
     */
    public static function signature(Element $root): ?Element
    {
        return self::children($root)[0][0] ?? null;
    }

    /**
     * Section 6.5 steps 1 and 3 to 7
     *
     * @param DateTimeImmutable $expired now minus the clock skew
     *
     * @throws Unsupported
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws LimitExceeded
     * @throws InvalidKey
     * @throws MixedContent
     */
    public static function read(Element $root, DateTimeImmutable $expired): EntityDescriptor
    {
        $children = self::children($root);
        $entityId = Uri::read(Schema::attribute($root, 'md:EntityDescriptor', 'entityID'));
        $validUntil = Attributes::optional($root, new Name(null, 'validUntil'));
        $validUntil = $validUntil === null ? null : Time::read($validUntil);
        if ($validUntil instanceof DateTimeImmutable && $validUntil <= $expired) {
            throw new OutsideValidityWindow('The metadata is past its validUntil (M-7).');
        }
        if ($children[2] !== [] && $children[3] !== []) {
            throw new MalformedMessage('An md:EntityDescriptor holds role descriptors and an md:AffiliationDescriptor (M-5).');
        }
        $identityProviders = [];
        $serviceProviders = [];
        foreach ($children[2] as $role) {
            if (Schema::md('IDPSSODescriptor')->matches($role) && RoleReader::supportsSaml2($role, 'md:IDPSSODescriptor')) {
                $identityProviders[] = $role;
            }
            if (Schema::md('SPSSODescriptor')->matches($role) && RoleReader::supportsSaml2($role, 'md:SPSSODescriptor')) {
                $serviceProviders[] = $role;
            }
        }
        if (count($identityProviders) > 1) {
            throw new MalformedMessage('An md:EntityDescriptor holds more than one md:IDPSSODescriptor for SAML 2.0 (section 6.5).');
        }
        if (count($serviceProviders) > 1) {
            throw new MalformedMessage('An md:EntityDescriptor holds more than one md:SPSSODescriptor for SAML 2.0 (section 6.5).');
        }
        if ($identityProviders === [] && $serviceProviders === []) {
            throw new MalformedMessage('An md:EntityDescriptor holds no md:IDPSSODescriptor and no md:SPSSODescriptor for SAML 2.0 (M-13).');
        }

        return new EntityDescriptor(
            $entityId,
            $validUntil,
            $identityProviders === [] ? null : RoleReader::identityProvider($identityProviders[0], $entityId, $expired),
            $serviceProviders === [] ? null : RoleReader::serviceProvider($serviceProviders[0], $entityId, $expired),
        );
    }

    /**
     * @throws Unsupported
     * @throws MalformedMessage
     *
     * @return list<list<Element>>
     */
    private static function children(Element $root): array
    {
        if (Schema::md('EntitiesDescriptor')->matches($root)) {
            throw new Unsupported('md:EntitiesDescriptor, aggregated metadata, is not supported (section 8).');
        }
        if (! Schema::md('EntityDescriptor')->matches($root)) {
            throw new MalformedMessage('The root of the metadata is not an md:EntityDescriptor (section 6.5).');
        }

        return Schema::children($root, 'md:EntityDescriptor', [
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::md('Extensions'), 0, 1),
            new Particle(
                'role descriptor',
                [
                    Schema::md('RoleDescriptor'),
                    Schema::md('IDPSSODescriptor'),
                    Schema::md('SPSSODescriptor'),
                    Schema::md('AuthnAuthorityDescriptor'),
                    Schema::md('AttributeAuthorityDescriptor'),
                    Schema::md('PDPDescriptor'),
                ],
                0,
                Particle::UNBOUNDED,
            ),
            Particle::of(Schema::md('AffiliationDescriptor'), 0, 1),
            Particle::of(Schema::md('Organization'), 0, 1),
            Particle::of(Schema::md('ContactPerson'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('AdditionalMetadataLocation'), 0, Particle::UNBOUNDED),
        ]);
    }
}
