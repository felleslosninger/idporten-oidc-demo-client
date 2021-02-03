# idporten-oidc-test-client

## Innlogging med ID-porten
ID-porten testklient demonstrerer innlogging med ID-portens OpenID Connect-grensesnitt.  Brukeren kan justere enkelte parametere på autorisasjonsforespørselen, autentisere seg i ID-porten og se resultatet.  Interaksjonene med ID-porten samles opp på resultatsider og feilsider.  

Applikasjonen støtter innlogging med ID-porten med:

* OpenID Connect Discovery for å lese konfigurasjon fra ID-porten - https://openid.net/specs/openid-connect-discovery-1_0.html

* JSON Web Keys leses fra ID-porten for validering av tokens - https://tools.ietf.org/html/rfc7517

* OpenID Connect Authorization code flow for innlogging - https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowAuth
  * klientautentisering med client_secret basic, client_secret_post eller private_keyt_jwt for uthenting av tokens
  * PKCE ved klientautentisering - https://tools.ietf.org/html/rfc7636
  * Validering av state og nonce
  * Validering av ID-token
* OpenID Connect RP-Initiated Logout for utlogging - https://openid.net/specs/openid-connect-rpinitiated-1_0.html


## Bregrensninger
### Applikasjonen er ikke et startpunkt for å integrere med ID-porten
Applikasjonen er ikke et eksempel på hvordan en Spring Boot-basert applikasjon kan integreres med ID-porten.  Applikasjonen samler opp interaksjonene og viser hva som skjer under en autentisering.  Integrasjon mot ID-porten fra en kundeapplikasjon, gjøres best med kjente biblioteker på den plattformen kunden selv foretrekker.  

### Applikasjonen kan ikke brukes til å teste ID-portens grensesnitt i detalj
Applikasjonen tilbyr for lite funksjonalitet til å teste ID-porten i detalj.  Det blir begrenset av mengden parametere som benyttes av applikasjonen, muligheten til å manipulere dette, samt at applikasjonen bruker biblioteker som gjør sjekker før interaksjon med ID-porten.  Til detaljert testing har vi andre og mer egnede verktøy internt.