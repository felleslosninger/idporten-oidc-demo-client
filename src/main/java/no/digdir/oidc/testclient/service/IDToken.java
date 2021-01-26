package no.digdir.oidc.testclient.service;

import com.nimbusds.openid.connect.sdk.claims.IDTokenClaimsSet;
import lombok.AllArgsConstructor;
import lombok.Getter;


@AllArgsConstructor
@Getter
public class IDToken {

    private String personIdentifier;
    private IDTokenClaimsSet claimsSet;
    
}
