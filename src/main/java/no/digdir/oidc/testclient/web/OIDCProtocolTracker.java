package no.digdir.oidc.testclient.web;

import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.URI;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Slf4j
public class OIDCProtocolTracker implements Serializable {

    private String authorizationRequest;
    private String authorizationResponse;

    private String logoutRequest;
    private String logoutResponse;

    private String tokenRequest;
    private String tokenResponse;


    public List<TrackedInteraction> getLogoutInteraction() {
        return Arrays.asList(
                TrackedInteraction.builder().id("logoutRequest").text("Logout request").interaction(logoutRequest).build(),
                TrackedInteraction.builder().id("logoutResponse").text("Logout response").interaction(logoutResponse).build())
                .stream()
                .filter(interaction -> StringUtils.hasText(interaction.getInteraction()))
                .collect(Collectors.toList());
    }

    public List<TrackedInteraction> getLoginInteraction() {
        return Arrays.asList(
                TrackedInteraction.builder().id("authorizationRequest").text("Authorization request").interaction(authorizationRequest).build(),
                TrackedInteraction.builder().id("authorizationResponse").text("Authorization response").interaction(authorizationResponse).build(),
                TrackedInteraction.builder().id("tokenRequest").text("Token request").interaction(tokenRequest).build(),
                TrackedInteraction.builder().id("tokenResponse").text("Token response").interaction(tokenResponse).build())
                .stream()
                .filter(interaction -> StringUtils.hasText(interaction.getInteraction()))
                .collect(Collectors.toList());
    }

    @Builder
    @Data
    static class TrackedInteraction {

        private String id;
        private String text;
        private String interaction;

    }


    public static OIDCProtocolTracker set(HttpSession session, OIDCProtocolTracker protocolTracker) {
        session.setAttribute("protocolTracker", protocolTracker);
        log.info("Connected protocol tracker to session {}", session.getId());
        return protocolTracker;
    }

    public static OIDCProtocolTracker get(HttpSession session) {
        return (OIDCProtocolTracker) session.getAttribute("protocolTracker");
    }

    public static OIDCProtocolTracker create(HttpSession session) {
        OIDCProtocolTracker protocolTracker = new OIDCProtocolTracker();
        session.setAttribute("protocolTracker", protocolTracker);
        log.info("Created new protocol tracker for session {}", session.getId());
        return protocolTracker;
    }

    public static OIDCProtocolTracker getOrCreate(HttpSession session) {
        OIDCProtocolTracker oidcProtocolTracker = get(session);
        if (oidcProtocolTracker == null) {
            log.info("No protocol tracker found for session {}", session.getId());
            return create(session);
        }
        return oidcProtocolTracker;
    }

    public static OIDCProtocolTracker trackAuthorizationRequest(HttpSession session, URI authorizationRequest) {
        OIDCProtocolTracker protocolTracker = create(session);
        protocolTracker.setAuthorizationRequest(formatUri(authorizationRequest));
        return protocolTracker;
    }

    public static OIDCProtocolTracker trackAuthorizationResponse(HttpSession session, URI authorizationResponse) {
        OIDCProtocolTracker protocolTracker = getOrCreate(session);
        protocolTracker.setAuthorizationResponse(formatUri(authorizationResponse));
        return protocolTracker;
    }

    public static OIDCProtocolTracker trackLogoutRequest(HttpSession session, URI logoutRequest) {
        OIDCProtocolTracker protocolTracker = getOrCreate(session);
        protocolTracker.setLogoutRequest(formatUri(logoutRequest));
        return protocolTracker;
    }

    public static OIDCProtocolTracker trackLogoutResponse(HttpSession session, URI logoutResponse) {
        OIDCProtocolTracker protocolTracker = getOrCreate(session);
        protocolTracker.setLogoutResponse(formatUri(logoutResponse));
        return protocolTracker;
    }

    public static OIDCProtocolTracker trackTokenRequest(HttpSession session, HTTPRequest tokenRequest) {
        OIDCProtocolTracker protocolTracker = getOrCreate(session);
        StringBuilder sb = new StringBuilder()
                .append(tokenRequest.getMethod())
                .append(' ')
                .append(tokenRequest.getURI())
                .append('\n');
        tokenRequest.getHeaderMap().forEach(
                (header, value) -> sb.append(header).append(": ").append("Authorization".equals(header) && value.get(0).startsWith("Basic ") ? "Basic ***" : String.join(" ", value)).append('\n')
        );
        sb.append('\n');


        sb.append(
                String.join("&\n",
                        tokenRequest.getQueryParameters().entrySet()
                                .stream()
                                .map(entry ->
                                {
                                    StringBuilder s = new StringBuilder(entry.getKey()).append('=');
                                    if ("client_secret".equals(entry.getKey())) {
                                        s.append("***");
                                    } else {
                                        s.append(String.join("+", entry.getValue()));
                                    }
                                    return s.toString();
                                })
                                .collect(Collectors.toList())
                ));

        protocolTracker.setTokenRequest(sb.toString());
        return protocolTracker;
    }

    public static OIDCProtocolTracker trackTokenResponse(HttpSession session, HTTPResponse tokenResponse) {
        OIDCProtocolTracker protocolTracker = getOrCreate(session);
        StringBuilder sb = new StringBuilder();
        tokenResponse.getHeaderMap().forEach((header, value) -> sb.append(header).append(':').append(String.join(" ", value)));
        sb.append("\n\n");
        sb.append(tokenResponse.getContent());
        protocolTracker.setTokenResponse(sb.toString());
        return protocolTracker;
    }

    protected static String formatUri(URI uri) {
        StringBuilder sb = new StringBuilder()
                .append(uri.getScheme())
                .append("://")
                .append(uri.getAuthority())
                .append(uri.getPath())
                .append('?')
                .append('\n');
        return uri.toString().replaceAll("\\?", "?\n")
                .replaceAll("&", "&\n");
    }


}
