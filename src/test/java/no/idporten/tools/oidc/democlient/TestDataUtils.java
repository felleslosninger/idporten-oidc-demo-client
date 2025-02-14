package no.idporten.tools.oidc.democlient;

import com.nimbusds.jwt.JWTClaimsSet;

/**
 * Utilities for test data.
 */
public class TestDataUtils {

    public static String testUserPersonIdentifier() {
        return "11223312345";
    }

    public static JWTClaimsSet idTokenClaimsSet(String personIDentifier) {
        try {
            return JWTClaimsSet.parse(String.format("""
                    {
                      "sub" : "sub-11223312345",
                      "aud" : "idporten-oidc-demo-client",
                      "acr" : "Level4",
                      "amr" : [ "testid2" ],
                      "auth_time" : 1612351397,
                      "iss" : "https://c2id-demo.westeurope.cloudapp.azure.com",
                      "pid" : "11223312345",
                      "exp" : 1612351517,
                      "locale" : "nb",
                      "iat" : 1612351397,
                      "nonce" : "QrxBHIQb-_iSwg98FgJgn9X1j3USkFmEvOnDaLY79HA",
                      "sid" : "s322f2-CbxLN8Hm-kQew8f0w8HwE7l1-HSCKmrGYGN4"
                    }""", personIDentifier));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
