package no.idporten.tools.oidc.democlient.service;

import lombok.Builder;
import lombok.Data;

@Builder
@Data
public class ProtocolInteraction {

    private String id;
    private String text;
    private String interaction;

}
