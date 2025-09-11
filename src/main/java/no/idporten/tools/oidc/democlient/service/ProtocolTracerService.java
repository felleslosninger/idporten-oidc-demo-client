package no.idporten.tools.oidc.democlient.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.nimbusds.jwt.JWT;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import jakarta.servlet.http.HttpSession;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;


@Slf4j
@Service
public class ProtocolTracerService {

    public static ProtocolTrace set(HttpSession session, ProtocolTrace protocolTrace) {
        session.setAttribute("protocolTrace", protocolTrace);
        log.info("Connected protocol trace to session {}", session.getId());
        return protocolTrace;
    }

    public static ProtocolTrace get(HttpSession session) {
        return (ProtocolTrace) session.getAttribute("protocolTrace");
    }

    public static ProtocolTrace create(HttpSession session) {
        ProtocolTrace protocolTrace = new ProtocolTrace();
        session.setAttribute("protocolTrace", protocolTrace);
        log.info("Created new protocol trace for session {}", session.getId());
        return protocolTrace;
    }

    public static ProtocolTrace getOrCreate(HttpSession session) {
        ProtocolTrace oidcprotocolTrace = get(session);
        if (oidcprotocolTrace == null) {
            log.info("No protocol trace found for session {}", session.getId());
            return create(session);
        }
        return oidcprotocolTrace;
    }

    public ProtocolTrace traceAuthorizationRequest(HttpSession session, URI authorizationRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setAuthorizationRequest(
                ProtocolInteraction.builder()
                        .id("authorizationRequest")
                        .text("Authorization request")
                        .interaction(formatUri(authorizationRequest))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceAuthorizationResponse(HttpSession session, URI authorizationResponse) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setAuthorizationResponse(
                ProtocolInteraction.builder()
                        .id("authorizationResponse")
                        .text("Authorization response")
                        .interaction(formatUri(authorizationResponse))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceAuthorizationResponseJWT(HttpSession session, JWT jwt) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setAuthorizationResponseJWT(ProtocolInteraction.builder()
                .id("authorizationResponseJWT")
                .text("Validated authorization response")
                .interaction(formatJWT(jwt))
                .build());
        return protocolTrace;
    }

    public ProtocolTrace tracePushedAuthorizationRequest(HttpSession session, HTTPRequest pushedAuthorizationRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setPushedAuthorizationRequest(
                ProtocolInteraction.builder()
                        .id("pushedAuthorizationRequest")
                        .text("Pushed authorization request")
                        .interaction(formatHTTPRequest(pushedAuthorizationRequest))
                        .build());

        return protocolTrace;
    }

    public ProtocolTrace tracePushedAuthorizationResponse(HttpSession session, HTTPResponse pushedAuthorizationResponse) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setPushedAuthorizationResponse(
                ProtocolInteraction.builder()
                        .id("pushedAuthorizationResponse")
                        .text("Pushed authorization response")
                        .interaction(formatHTTPResponse(pushedAuthorizationResponse))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceLogoutRequest(HttpSession session, URI logoutRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setLogoutRequest(
                ProtocolInteraction.builder()
                        .id("logoutRequest")
                        .text("Logout request")
                        .interaction(formatUri(logoutRequest))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceLogoutRequest(HttpSession session, String logoutRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setLogoutRequest(
                ProtocolInteraction.builder()
                        .id("logoutRequest")
                        .text("Logout request")
                        .interaction(logoutRequest)
                        .build());
        return protocolTrace;
    }


    public ProtocolTrace traceLogoutResponse(HttpSession session, URI logoutResponse) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setLogoutResponse(
                ProtocolInteraction.builder()
                        .id("logoutResponse")
                        .text("Logout response")
                        .interaction(formatUri(logoutResponse))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceFrontChannelLogoutRequest(HttpSession session, URI frontChannelLogoutRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setLogoutResponse(
                ProtocolInteraction.builder()
                        .id("frontChannelLogoutRequest")
                        .text("Front channel logout request")
                        .interaction(formatUri(frontChannelLogoutRequest))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceTokenRequest(HttpSession session, HTTPRequest tokenRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setTokenRequest(
                ProtocolInteraction.builder()
                        .id("tokenRequest")
                        .text("Token request")
                        .interaction(formatHTTPRequest(tokenRequest))
                        .build());

        return protocolTrace;
    }

    public ProtocolTrace traceUserInfoRequest(HttpSession session, HTTPRequest userInfoRequest) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setUserInfoRequest(
                ProtocolInteraction.builder()
                        .id("userInfoRequest")
                        .text("UserInfo request")
                        .interaction(formatHTTPRequest(userInfoRequest))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceUserInfoResponse(HttpSession session, HTTPResponse userInfoResponse) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setUserInfoResponse(
                ProtocolInteraction.builder()
                        .id("userInfoResponse")
                        .text("UserInfo response")
                        .interaction(formatHTTPResponse(userInfoResponse))
                        .build());
        return protocolTrace;
    }

    public ProtocolTrace traceTokenResponse(HttpSession session, HTTPResponse tokenResponse) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setTokenResponse(ProtocolInteraction.builder()
                .id("tokenResponse")
                .text("Token response")
                .interaction(formatHTTPResponse(tokenResponse))
                .build());
        return protocolTrace;
    }

    public ProtocolTrace traceValidatedIdToken(HttpSession session, JWT jwt) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setValidatedIdToken(ProtocolInteraction.builder()
                .id("idToken")
                .text("Validated id_token")
                .interaction(formatJWT(jwt))
                .build());
        return protocolTrace;
    }

    public ProtocolTrace traceBearerAccessToken(HttpSession session, String accessToken) {
        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setBearerAccessToken(ProtocolInteraction.builder()
                .id("accessToken")
                .text("Bearer access_token")
                .interaction(accessToken)
                .build());
        return protocolTrace;
    }

    private WarningLevel getHighestWarningLevel(Set<WarningLevel> levels) {
        if (levels.contains(WarningLevel.ERROR)) {
            return WarningLevel.ERROR;
        } else if (levels.contains(WarningLevel.WARNING)) {
            return WarningLevel.WARNING;
        } else if (levels.contains(WarningLevel.INFO)) {
            return WarningLevel.INFO;
        } else  {
            return null;
        }
    }

    public ProtocolTrace traceX509SigningCertificate(HttpSession session, List<X509Certificate> list, String jwksEndpoint, Map<WarningLevel, List<String>> validationResults, boolean enableWarning) {
        final var encoder = Base64.getEncoder();
        final var trace = new StringBuilder(2048);

        for (var level : validationResults.keySet()) {
            final var message = validationResults.get(level);
            trace.append(level).append(": ");
            trace.append(message);

        }

        trace.append("\n");

        for (X509Certificate cert : list) {
            try {
                final var base64 = encoder.encodeToString(cert.getEncoded());
                final var content = String.format("""
                    ---
                    Base64: %s
                    Issued date: %s
                    Expiration date: %s
                    Serial number: %s
                    ---
                    """, base64, cert.getNotBefore(), cert.getNotAfter(), cert.getSerialNumber());
                trace.append(content);
            } catch (CertificateEncodingException e) {
                throw new RuntimeException("Eh!");
            }
        }

        ProtocolTrace protocolTrace = getOrCreate(session);
        protocolTrace.setSignatureChainX5c(ProtocolInteraction.builder()
                .id("oidcSignatureChain")
                .text("Issuer X.509 Signature Chain (x5c)")
                .interaction(trace.toString())
                .warningLevel(getHighestWarningLevel(validationResults.keySet()))
                .build());
        return protocolTrace;
    }

    protected static String formatJson(String json) {
        try {
            ObjectMapper objectMapper = new ObjectMapper();
            return objectMapper.enable(SerializationFeature.INDENT_OUTPUT).writeValueAsString(objectMapper.readTree(json));
        } catch (JsonProcessingException e) {
            return json;
        }
    }

    protected static String formatJWT(JWT jwt) {
        try {
            return formatJson(jwt.getHeader().toString()) +
                    "\n.\n" +
                    formatJson(jwt.getJWTClaimsSet().toString());
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
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

    protected static String formatHTTPRequest(HTTPRequest httpRequest) {
        StringBuilder sb = new StringBuilder()
                .append(httpRequest.getMethod())
                .append(' ')
                .append(httpRequest.getURI())
                .append('\n');
        httpRequest.getHeaderMap().forEach(
                (header, value) -> sb.append(header)
                        .append(": ")
                        .append("Authorization".equals(header) && value.getFirst().startsWith("Basic ")
                                ? "Basic ***"
                                : String.join(" ", value))
                        .append('\n')
        );
        sb.append('\n');
        sb.append(
                httpRequest.getQueryParameters().entrySet()
                        .stream()
                        .map(entry ->
                                new StringBuilder(entry.getKey())
                                        .append('=')
                                        .append(
                                                switch (entry.getKey()) {
                                                    case "client_secret" -> "***";
                                                    case "client_assertion" -> maskJwt(entry.getValue().getFirst());
                                                    default -> String.join("+", entry.getValue());
                                                }))
                        .collect(Collectors.joining("&\n")));
        return sb.toString();
    }

    private static String maskJwt(String jwt) {
        // remove signature from jwt to prevent replay
        return jwt.replaceAll("(?<header>[^.]+)\\.(?<body>[^.]+)\\.[^.]+$", "${header}.${body}.***");
    }

    protected static String formatHTTPResponse(HTTPResponse httpResponse) {
        StringBuilder sb = new StringBuilder();
        httpResponse.getHeaderMap().forEach((header, value) ->
                sb.append(header)
                        .append(':')
                        .append(String.join(" ", value))
                        .append('\n'));
        sb.append("\n");
        sb.append(formatJson(httpResponse.getContent()));
        return sb.toString();
    }

}
