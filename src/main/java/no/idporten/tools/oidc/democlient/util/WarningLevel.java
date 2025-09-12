package no.idporten.tools.oidc.democlient.util;

public enum WarningLevel {
    INFO,
    WARN,
    ERROR;

    public String toLowerCase()
    {
        return name().toLowerCase();
    }
}

