package no.digdir.oidc.testclient;

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
            return JWTClaimsSet.parse(String.format("{\n" +
                    "  \"sub\" : \"11223312345\",\n" +
                    "  \"aud\" : \"idporten-test-client\",\n" +
                    "  \"acr\" : \"Level4\",\n" +
                    "  \"amr\" : [ \"testid2\" ],\n" +
                    "  \"auth_time\" : 1612351397,\n" +
                    "  \"iss\" : \"https://c2id-demo.westeurope.cloudapp.azure.com/c2id\",\n" +
                    "  \"pid\" : \"11223312345\",\n" +
                    "  \"exp\" : 1612351517,\n" +
                    "  \"locale\" : \"nb\",\n" +
                    "  \"iat\" : 1612351397,\n" +
                    "  \"nonce\" : \"QrxBHIQb-_iSwg98FgJgn9X1j3USkFmEvOnDaLY79HA\",\n" +
                    "  \"sid\" : \"s322f2-CbxLN8Hm-kQew8f0w8HwE7l1-HSCKmrGYGN4\"\n" +
                    "}", personIDentifier));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
