package no.digdir.oidc.testclient.service;

import lombok.Data;

import java.io.Serializable;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Data
public class ProtocolTrace implements Serializable {

    private ProtocolInteraction authorizationRequest;
    private ProtocolInteraction authorizationResponse;
    private ProtocolInteraction tokenRequest;
    private ProtocolInteraction tokenResponse;
    private ProtocolInteraction validatedIdToken;
    private ProtocolInteraction logoutRequest;
    private ProtocolInteraction logoutResponse;

    public List<ProtocolInteraction> getLogoutInteraction() {
        return Stream.of(logoutRequest, logoutResponse)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public List<ProtocolInteraction> getLoginInteraction() {
        return Stream.of(authorizationRequest, authorizationResponse, tokenRequest, tokenResponse, validatedIdToken)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    public List<ProtocolInteraction> getAllInteraction() {
        return Stream.of(getLoginInteraction(), getLogoutInteraction()).flatMap(List::stream).collect(Collectors.toList());
    }

}