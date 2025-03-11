package no.idporten.tools.oidc.democlient.service;

import lombok.Data;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
public class ProtocolTrace implements Serializable {

    private ProtocolInteraction pushedAuthorizationRequest;
    private ProtocolInteraction pushedAuthorizationResponse;
    private ProtocolInteraction authorizationRequest;
    private ProtocolInteraction authorizationResponse;
    private ProtocolInteraction tokenRequest;
    private ProtocolInteraction tokenResponse;
    private ProtocolInteraction validatedIdToken;
    private ProtocolInteraction bearerAccessToken;
    private ProtocolInteraction userInfoRequest;
    private ProtocolInteraction userInfoResponse;
    private ProtocolInteraction logoutRequest;
    private ProtocolInteraction logoutResponse;

    public List<ProtocolInteraction> getLogoutInteraction() {
        return Stream.of(logoutRequest, logoutResponse)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public List<ProtocolInteraction> getLoginInteraction() {
        return Stream.of(pushedAuthorizationRequest, pushedAuthorizationResponse, authorizationRequest, authorizationResponse, tokenRequest, tokenResponse, validatedIdToken, bearerAccessToken, userInfoRequest, userInfoResponse)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public List<ProtocolInteraction> getAllInteraction() {
        return Stream.of(getLoginInteraction(), getLogoutInteraction()).flatMap(List::stream).collect(Collectors.toList());
    }

}