<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Metadata;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\OutsideValidityWindow;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Internal\Particle;
use Beffroi\Saml2\Model\Internal\Schema;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Saml2\Model\Value\Counts;
use Beffroi\Saml2\Model\Value\Time;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use function count;
use DateTimeImmutable;
use Dom\Element;
use function in_array;
use function preg_split;
use const PREG_SPLIT_NO_EMPTY;

/**
 * Section 6.5 steps 4 to 7
 *
 * @internal
 */
final readonly class RoleReader
{
    /**
     * @param string $element the name of the role in the schema
     *
     * @throws MalformedMessage
     */
    public static function supportsSaml2(Element $role, string $element): bool
    {
        $protocols = preg_split(
            '~[\x20\x09\x0A\x0D]+~',
            Schema::attribute($role, $element, 'protocolSupportEnumeration'),
            flags: PREG_SPLIT_NO_EMPTY,
        );

        return in_array(Saml::PROTOCOL, $protocols === false ? [] : $protocols, true);
    }

    /**
     * @param DateTimeImmutable $expired now minus the clock skew
     *
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws LimitExceeded
     * @throws Unsupported
     * @throws InvalidKey
     * @throws MixedContent
     */
    public static function identityProvider(
        Element $role,
        string $entityId,
        DateTimeImmutable $expired,
    ): IdentityProvider {
        $children = Schema::children($role, 'md:IDPSSODescriptor', [
            ...self::ssoDescriptor(),
            Particle::of(Schema::md('SingleSignOnService'), 1, Particle::UNBOUNDED),
            Particle::of(Schema::md('NameIDMappingService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('AssertionIDRequestService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('AttributeProfile'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::saml('Attribute'), 0, Particle::UNBOUNDED),
        ]);
        self::validUntil($role, $expired);
        EndpointReader::bound($children[9], 'md:SingleSignOnService');
        EndpointReader::bound($children[6], 'md:SingleLogoutService');
        self::boundFormats($children[8]);
        [$signing, $encryption] = KeyDescriptorReader::read($children[2]);
        $singleSignOn = EndpointReader::endpoints($children[9], 'md:SingleSignOnService');
        $singleLogout = EndpointReader::endpoints($children[6], 'md:SingleLogoutService');
        if ($singleSignOn === []) {
            throw new MalformedMessage('The md:IDPSSODescriptor lists no md:SingleSignOnService on HTTP-Redirect or HTTP-POST (section 6.5).');
        }

        return new IdentityProvider(
            $entityId,
            $signing,
            $encryption,
            $singleSignOn,
            $singleLogout,
            self::formats($children[8]),
            self::flag($role, 'WantAuthnRequestsSigned'),
        );
    }

    /**
     * @param DateTimeImmutable $expired now minus the clock skew
     *
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     * @throws LimitExceeded
     * @throws Unsupported
     * @throws InvalidKey
     * @throws MixedContent
     */
    public static function serviceProvider(
        Element $role,
        string $entityId,
        DateTimeImmutable $expired,
    ): ServiceProvider {
        $children = Schema::children($role, 'md:SPSSODescriptor', [
            ...self::ssoDescriptor(),
            Particle::of(Schema::md('AssertionConsumerService'), 1, Particle::UNBOUNDED),
            Particle::of(Schema::md('AttributeConsumingService'), 0, Particle::UNBOUNDED),
        ]);
        self::validUntil($role, $expired);
        EndpointReader::bound($children[9], 'md:AssertionConsumerService');
        EndpointReader::bound($children[6], 'md:SingleLogoutService');
        self::boundFormats($children[8]);
        [$signing, $encryption] = KeyDescriptorReader::read($children[2]);
        $assertionConsumers = EndpointReader::assertionConsumerServices($children[9]);
        $singleLogout = EndpointReader::endpoints($children[6], 'md:SingleLogoutService');
        if ($assertionConsumers->endpoints === []) {
            throw new MalformedMessage('The md:SPSSODescriptor lists no md:AssertionConsumerService on HTTP-POST (section 6.5).');
        }

        return new ServiceProvider(
            $entityId,
            $signing,
            $encryption,
            $assertionConsumers,
            $singleLogout,
            self::formats($children[8]),
            self::flag($role, 'AuthnRequestsSigned'),
            self::flag($role, 'WantAssertionsSigned'),
        );
    }

    /**
     * SAML Metadata §2.4.1, §2.4.2
     *
     * @return list<Particle> the key descriptors at 2, the single logout services at 6, the NameID formats at 8
     */
    private static function ssoDescriptor(): array
    {
        return [
            Particle::of(Schema::ds('Signature'), 0, 1),
            Particle::of(Schema::md('Extensions'), 0, 1),
            Particle::of(Schema::md('KeyDescriptor'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('Organization'), 0, 1),
            Particle::of(Schema::md('ContactPerson'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('ArtifactResolutionService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('SingleLogoutService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('ManageNameIDService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('NameIDFormat'), 0, Particle::UNBOUNDED),
        ];
    }

    /**
     * Section 6.5 step 4
     *
     * A past validUntil refuses the whole metadata rather than dropping the role.
     *
     * @throws MalformedMessage
     * @throws OutsideValidityWindow
     */
    private static function validUntil(Element $role, DateTimeImmutable $expired): void
    {
        $validUntil = Attributes::optional($role, new Name(null, 'validUntil'));
        if ($validUntil !== null && Time::read($validUntil) <= $expired) {
            throw new OutsideValidityWindow('A role of the metadata is past its validUntil (M-7).');
        }
    }

    /**
     * @param list<Element> $formats
     *
     * @throws LimitExceeded
     */
    private static function boundFormats(array $formats): void
    {
        Counts::check(
            count($formats),
            Counts::NAME_ID_FORMATS,
            'A role descriptor holds more than 16 md:NameIDFormat, the bound of section 7 (M-17).',
        );
    }

    /**
     * @param list<Element> $formats
     *
     * @throws MixedContent
     *
     * @return list<NameIdFormat>
     */
    private static function formats(array $formats): array
    {
        $kept = [];
        foreach ($formats as $format) {
            $nameIdFormat = NameIdFormat::tryFrom(Text::of($format));
            if ($nameIdFormat !== null) {
                $kept[] = $nameIdFormat;
            }
        }

        return $kept;
    }

    /**
     * @throws MalformedMessage
     */
    private static function flag(Element $role, string $attribute): bool
    {
        $value = Attributes::optional($role, new Name(null, $attribute));

        return $value !== null && Boolean::read($value);
    }
}
