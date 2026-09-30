<?php

declare(strict_types=1);

namespace Beffroi\Saml2\Model\Internal\Metadata;

use Beffroi\Saml2\Model\Assertion\NameIdFormat;
use Beffroi\Saml2\Model\Exception\LimitExceeded;
use Beffroi\Saml2\Model\Exception\MalformedMessage;
use Beffroi\Saml2\Model\Exception\Unsupported;
use Beffroi\Saml2\Model\Metadata\IdentityProvider;
use Beffroi\Saml2\Model\Metadata\ServiceProvider;
use Beffroi\Saml2\Model\Saml;
use Beffroi\Saml2\Model\Value\Boolean;
use Beffroi\Xml\Core\Attributes;
use Beffroi\Xml\Core\Exception\MixedContent;
use Beffroi\Xml\Core\Name;
use Beffroi\Xml\Core\Text;
use Beffroi\Xml\Dsig\Exception\InvalidKey;
use function count;
use Dom\Element;
use function in_array;
use function preg_split;
use const PREG_SPLIT_NO_EMPTY;

/**
 * The md:IDPSSODescriptor and md:SPSSODescriptor of an entity (section 6.5 steps 4 to 7), each read in the order and
 * with the cardinality of the schema (M-5): the keys, the endpoints, the NameID formats of SAML Core §8.3 and the
 * flags. The children the schema allows and the package does not use are skipped in their place: md:Extensions,
 * md:Organization, md:ContactPerson, md:ArtifactResolutionService, md:ManageNameIDService, md:NameIDMappingService,
 * md:AssertionIDRequestService, md:AttributeProfile, saml:Attribute and md:AttributeConsumingService, and a role's own
 * ds:Signature, which the entity's covers when readSigned() verified it.
 *
 * @internal
 */
final readonly class RoleReader
{
    private const int MAX_NAME_ID_FORMATS = 16;

    /**
     * Whether a role lists SAML 2.0 in its protocolSupportEnumeration, a list of URIs separated by whitespace; one
     * that does not is ignored (section 6.5 step 4).
     *
     * @param string $element the name of the role in the schema
     *
     * @throws MalformedMessage when the attribute is absent (M-5)
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
     * @throws MalformedMessage when the structure or a value is not the schema's, or no single sign-on service is on
     *                          HTTP-Redirect or HTTP-POST
     * @throws LimitExceeded when a count is over its bound of section 7 (M-17)
     * @throws Unsupported when a key is a ds:KeyValue alone (section 8)
     * @throws InvalidKey when a certificate is not the base64 of an RSA key of at least 2048 bits (D-16)
     * @throws MixedContent when an md:NameIDFormat holds an element (I-12)
     */
    public static function identityProvider(Element $role, string $entityId): IdentityProvider
    {
        $children = Schema::children($role, 'md:IDPSSODescriptor', [
            ...self::ssoDescriptor(),
            Particle::of(Schema::md('SingleSignOnService'), 1, Particle::UNBOUNDED),
            Particle::of(Schema::md('NameIDMappingService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('AssertionIDRequestService'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::md('AttributeProfile'), 0, Particle::UNBOUNDED),
            Particle::of(Schema::saml('Attribute'), 0, Particle::UNBOUNDED),
        ]);
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
     * @throws MalformedMessage when the structure or a value is not the schema's, or no assertion consumer service is
     *                          on HTTP-POST
     * @throws LimitExceeded when a count is over its bound of section 7 (M-17)
     * @throws Unsupported when a key is a ds:KeyValue alone (section 8)
     * @throws InvalidKey when a certificate is not the base64 of an RSA key of at least 2048 bits (D-16)
     * @throws MixedContent when an md:NameIDFormat holds an element (I-12)
     */
    public static function serviceProvider(Element $role, string $entityId): ServiceProvider
    {
        $children = Schema::children($role, 'md:SPSSODescriptor', [
            ...self::ssoDescriptor(),
            Particle::of(Schema::md('AssertionConsumerService'), 1, Particle::UNBOUNDED),
            Particle::of(Schema::md('AttributeConsumingService'), 0, Particle::UNBOUNDED),
        ]);
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
     * The sequence of SSODescriptorType, which both roles start with (SAML Metadata §2.4.1, §2.4.2): the key
     * descriptors at 2, the single logout services at 6, the NameID formats at 8.
     *
     * @return list<Particle>
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
     * @param list<Element> $formats
     *
     * @throws LimitExceeded when there are more than 16, dropped ones included (section 7)
     */
    private static function boundFormats(array $formats): void
    {
        if (count($formats) > self::MAX_NAME_ID_FORMATS) {
            throw new LimitExceeded('A role descriptor holds more than 16 md:NameIDFormat, the bound of section 7 (M-17).');
        }
    }

    /**
     * The formats of SAML Core §8.3, in order; any other URI, an empty one included, is dropped (section 6.5 step 7).
     *
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
     * A boolean attribute of M-6, absent meaning false (section 6.5 step 7).
     *
     * @throws MalformedMessage
     */
    private static function flag(Element $role, string $attribute): bool
    {
        $value = Attributes::optional($role, new Name(null, $attribute));

        return $value !== null && Boolean::read($value);
    }
}
