# idporten-oidc-demo-client — AI assistant instructions

Terse by design; optimized for AI use. Shared by [`CLAUDE.md`](../CLAUDE.md) and
[`copilot-instructions.md`](copilot-instructions.md).

Spring Boot 4 / Java 25 Thymeleaf web app: a demo OpenID Connect relying party for ID-porten, Ansattporten and
eIDAS. It runs the authorization code flow against a real provider and shows the user every protocol interaction.
One image, three deployments (`idporten-`, `ansattporten-`, `eidas-oidc-demo-client`) selected by Spring profile.
`README.md` (Norwegian) = purpose, supported features, limitations, how to run. It is explicitly *not* a reference
integration — keep it a demo, do not turn it into a library or a starting point for customers.

## Build, test, run

```bash
mvn test                                  # all tests (surefire; no failsafe, no coverage gate)
mvn -Dtest=ClassName test                 # single class; 'ClassName#method' for one method
mvn spring-boot:run -Dspring-boot.run.profiles=idporten,idporten-test   # needs OIDC_DEMO_CLIENT_SECRET
docker-compose up --build                 # profiles idporten,docker → local ID-porten stack (c2id:8080 on network `idporten`)
docker-compose -f docker-compose-test.yaml up --build   # profile docker-test → test.ansattporten.no
```

- Deps from GitHub Packages (`felleslosninger`): needs a `github` server in `~/.m2/settings.xml`; docker builds need
  `GIT_PACKAGE_TOKEN`/`GIT_PACKAGE_USERNAME` in the environment.
- Surefire attaches Mockito as a javaagent (`argLine` in `pom.xml`); keep that when touching surefire config.
- Outside the `test` profile the app resolves OIDC discovery from the issuer on startup and caches the JWKS
  (`IDPortenDemoClientApplication`); failure closes the context. A non-test profile needs network access to its issuer.
- Docker: port 7074, context path `/idporten-oidc-demo-client`, add `127.0.0.1 democlient` to the hosts file.
  Remote debug on 5888.

## Architecture

- Package `no.idporten.tools.oidc.democlient`. No database; the only outbound calls go to the OIDC provider. All
  state lives in the `HttpSession`: `state`, `nonce`, `code_verifier`, `id_token` and the
  `ProtocolTrace`.
- Endpoints (`TestClientController`): `GET /` form (query params `scopes`, `acrValues`, `uiLocales`,
  `authorizationDetails`, `prompt` pre-fill it — the "permlink") → `POST /authorize` (builds the request, renders
  `authorize.html` which meta-refreshes to the provider) → `GET /callback` (state check, token request, ID-token +
  acr + signing-certificate validation, userinfo when scope has `profile`) → `idtoken.html`. `GET /logout`
  (RP-initiated, auto-submit form from `HtmlFormService`) → `GET /logout/callback`; `GET /logout/frontchannel`.
  `GET /trace`, `GET /trace/clear`.
- `OIDCIntegrationService` wraps Nimbus `oauth2-oidc-sdk`: `AuthenticationRequest` when scope contains `openid`,
  plain `AuthorizationRequest` otherwise; optional PAR (feature switch), PKCE, JARM (`response-mode: query.jwt`),
  client auth `client_secret_basic | client_secret_post | client_secret_jwt | private_key_jwt` (keystore via
  `KeyStoreProvider`/`KeyProvider`). `IDTokenValidator`, `JARMValidator`, `RemoteJWKSet`, `OIDCProviderMetadata`
  are beans in `OIDCIntegrationConfiguration` (`@Profile("!test")`).
- `AcrValidator` rejects an ID token whose `acr` is not in the provider's `acr_values_supported` (discovery); the
  same list feeds the acr label on the form. There is deliberately no level ranking — do not reintroduce
  string-suffix or ordered-list checks. The product profiles only set the default `acr-value`.
- `ProtocolTracerService` records every request/response into the session's `ProtocolTrace` and formats it for
  display; it masks `Authorization: Basic`, `client_secret` and the signature of `client_assertion`. A new
  protocol step needs a field on `ProtocolTrace`, a `trace*` method, and a slot in `getLoginInteraction()` /
  `getLogoutInteraction()` — that list is the display order.
- `SignatureCertificateValidator` checks the first `x5c` cert of the signing key (expired / not yet valid /
  expires within `jwks-expiry-warning-days`) → `ValidationResult(WarningLevel, message)`, rendered as icons in the
  trace.
- Errors: throw `OIDCIntegrationException(message)` for anything the user should read; `TestClientControllerAdvice`
  renders `error.html` with that message. Any other exception → logged, generic error page. No JSON errors, no
  error ids.
- Observability: `idporten-actuator-4-starter` on 8090 (`/health`, `/info`, `/version`, `/prometheus`),
  `idporten-access-log-spring-boot-4-starter` (JSON access log; asserted in `TestClientControllerLoggingTest`),
  Logstash JSON app log from `logback-spring.xml` (plain console under `docker`/`docker-test`). No custom metrics.

## Configuration and profiles

- Prefix `oidc-demo-client.*`, one `@ConfigurationProperties` class per group in `config.properties`:
  `oidc-integration` (`OIDCIntegrationProperties`, validated; `afterPropertiesSet` enforces secret/keystore per
  auth method and derives `frontChannelLogoutUri`), `theme` (`ThemeProperties`: heading, `user-id-claim`, form
  defaults), `features` (`FeatureSwitchProperties`: `authorization-details-enabled`,
  `use-pushed-authorization-requests`, default off), `static.resources` (`StaticResourcesProperties`: designsystem
  host + `ds-version`), `csp-header` (list joined into the CSP header by `ContentSecurityPolicySecurityConfiguration`).
- Profile layering: `application.yaml` (base: actuator, timeouts, kubernetes import of `/etc/config/`)
  + product profile `idporten` | `ansattporten` | `eidas` (application name, theme, features)
  + environment profile `<product>-test` | `-systest` | `-prod` (issuer, client, redirect URIs, CSP hosts)
  or a local one: `docker` | `docker-test` | `eidas-docker`.
- Secrets are env vars (`${OIDC_DEMO_CLIENT_SECRET}`, `${OIDC_CLIENT_SECRET}`) supplied by the deployment. Never
  commit a real one; the `docker*` profiles' values are local-stack throwaways.
- Tests use `src/test/resources/application-test.yaml` (+ `unitporten`) and `OIDCIntegrationTestConfiguration`
  (parsed metadata, mocked `RemoteJWKSet`/`IDTokenValidator`). Every `@SpringBootTest` needs
  `@ActiveProfiles("test")`, `@Import(OIDCIntegrationTestConfiguration.class)` and `@MockitoBean JARMValidator`,
  or the context tries to reach a real issuer.
- New config: property on the class + the profile yaml(s) where it differs + `README.md` if user-visible.
  Deployment-only values (env vars, active profiles, secrets) live in `felleslosninger/idporten-cd`.

## Templates and static resources

- Thymeleaf under `templates/`; shared `fragments/header.html` (head, links, heading), `footer.html` (scripts),
  `protocoltrace.html`. Model attributes `theme`, `features`, `staticResourcesDsBaseUri` are added by
  `TestClientControllerAdvice` for every view, error pages included.
- UI is Digdir designsystemet (`ds-*` classes, `data-variant`, `data-color`, `data-size`) loaded from
  `static.idporten.no/ds/<ds-version>`; Inter font from altinncdn.no. Local CSS: `layers.css` (layer order
  bootstrap < ds), `main.css`, `bootstrap.css` (layout only), `override.css`. Do not reintroduce Bootstrap JS or
  icons — they were removed on purpose.
- Local scripts are loaded with Subresource Integrity. Editing `static/dcscript-0.5.js` or `static/permlink.js`
  means recomputing the `integrity` attribute in the template
  (`openssl dgst -sha384 -binary <file> | base64`) or the browser silently refuses the script. Versioned file
  names (`dcscript-0.5.js`, `submitform-0.1.2.js`) are bumped on change.
- CSP is strict (`script-src 'self' …`): no inline `<script>` or `style=`. A new external host must be added to
  `csp-header` in every environment profile, not just the one you tested.

## Check upstream before changing

The notes above are a snapshot, not a contract. Before changing an integration, re-verify against the upstream
repo and update the relevant section in the same PR. `gh` is authenticated here:

```bash
gh search code '<term>' --repo felleslosninger/<repo> --limit 10
gh api repos/<owner>/<repo>/contents/<path> --jq .content | base64 -d
```

| Changing | Check |
|---|---|
| actuator / health / info / version | `felleslosninger/idporten-actuator-starter` |
| access log fields | `felleslosninger/idporten-access-log-spring-boot-starter` |
| designsystem markup or `ds-version` | what `static.idporten.no/ds/<version>` actually serves; designsystemet.no docs |
| deployment, env vars, profiles, secrets | `felleslosninger/idporten-cd` `apps/{idporten,ansattporten,eidas}/*/*-oidc-demo-client/` |
| CI | `felleslosninger/github-workflows` (`ci-pr-checks`, `ci-spring-boot-build-publish-image`, `on-pr-label`) |
| user-facing behaviour | `felleslosninger/docs` — several `_docs/` pages link to the demo client (`gh search code 'demo-client' --repo felleslosninger/docs`) |

## Conventions

- Lombok: `@RequiredArgsConstructor` + `final` fields, `@Slf4j`; `@Data`/`@Builder` on plain holders. No
  hand-written constructors or loggers (`TestClientControllerAdvice` is legacy, don't copy it).
- Never log tokens, secrets, authorization codes or the person identifier (`pid`). They belong in the protocol
  trace shown to the user, masked the way `ProtocolTracerService` already masks them.
- A comment that fits on one line uses `//`, never `/* … */` or a `/** … */` block wrapped around one sentence.
  Keep `/** … */` for javadoc that spans lines or carries `@param`/`@return`.
- Tests: JUnit 5, `@Nested` + `@DisplayName` as "When … / then …"; Mockito (`@ExtendWith(MockitoExtension.class)`,
  `@InjectMocks`) for units; `@SpringBootTest` + `MockMvc` for the controller; `@ParameterizedTest` + `@CsvSource`
  for tables. `TestDataUtils` + BouncyCastle generate keys, certificates and JWTs. Only `*Test`, no `*IT`.
- Branch name is always the Jira id alone, e.g. `ID-6862`. Never work directly on `main`.
- Commits on the branch are a short description of the change, no Jira id. The **PR title** to `main` carries it:
  `ID-6862: …` (usually Norwegian) — that is what ends up in the `main` history. CI verifies the title
  (`ci-pr-checks` via `pr-checks.yml`): 10–100 chars and a prefix from `Bump,PF-,ID-`.
- `(INTERNAL-COMMIT)` in a title is appended by CI when a human adds the `internal` label (hides the PR from
  public release notes). Never type it yourself and never add the label.
- Every merge to `main` builds the image and opens image-update PRs in `idporten-cd` for all three systest apps
  (`call-buildimage.yml`). A change for one product is deployed to all three.
- PR: read `.github/pull_request_template.md` and use it. Fill `SAK:` with the Jira id and set the `Eigar:`
  checkboxes. `Kodeles:` is the reviewer's — leave it untouched.
- Keep the PR text short: one bare bullet per change, a few words each, e.g. `Legg til AI-instruksjonar`. No
  file lists, no parentheticals, no background on where something came from — the reviewer reads the diff.
- Anything covered by a checklist line gets no bullet. Merged dependabot PRs are stated only by ticking
  `Har oppdatert dependabots`; the same goes for `.trivyignore`, catalog-info and the rest of the list.
- Never tick `Vurdert Manual deploy`, `Vurdert "internal"` or `Har kjørt opp lokalt med docker-compose og testet
  en innlogging` — a human does those when the PR is ready.
- Never reword a checklist line or append notes to it. Copy the template text verbatim and only set `[x]`/`[ ]`;
  anything that needs saying goes in the bullets above the checklist.
- `Har oppdatert dependabots` means: list open dependabot PRs (`gh pr list --author app/dependabot`) and
  consider merging them into this branch so those PRs become redundant — fewer deploys. Requires the branch to
  be up to date with `main` first.
- `Evt nye avhengigheter … catalog-info`: `catalog-info.yaml` holds one Backstage component per deployment; a new
  runtime dependency on another component is declared there.
- Every PR: consider whether `README.md` needs updating — it is the only documentation in the repo.
