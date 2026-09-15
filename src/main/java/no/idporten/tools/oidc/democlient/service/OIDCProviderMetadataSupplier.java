package no.idporten.tools.oidc.democlient.service;

import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;

// Supplies the provider's current metadata. Outside the test profile every call re-reads the discovery document.
@FunctionalInterface
public interface OIDCProviderMetadataSupplier {

    OIDCProviderMetadata current();

}
