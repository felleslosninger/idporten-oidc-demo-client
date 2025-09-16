package no.idporten.tools.oidc.democlient.util;

public enum WarningLevel {
    INFO,
    WARNING,
    ERROR;

    public String toLowerCase()
    {
        return name().toLowerCase();
    }
}

