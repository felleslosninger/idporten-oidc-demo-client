package no.idporten.tools.oidc.democlient.service;

import lombok.Builder;
import lombok.Data;
import no.idporten.tools.oidc.democlient.util.WarningLevel;

@Builder
@Data
public class ProtocolInteraction {

    private String id;
    private String text;
    private String interaction;
    private WarningLevel warningLevel;

}
