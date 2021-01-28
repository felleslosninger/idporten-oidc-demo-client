package no.digdir.oidc.testclient;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;

@Slf4j
@RequiredArgsConstructor
@SpringBootApplication
public class IDPortenTestClientApplication {

	private final RemoteJWKSet remoteJWKSet;

	public static void main(String[] args) {
		SpringApplication.run(IDPortenTestClientApplication.class, args);
	}

	@EventListener
	public void loadOpenIDConnectResources(ApplicationReadyEvent event) {
		try {
			loadJwks();
		} catch (Exception e) {
			log.error("Failed to read metadata from OpenID Connect provider", e);
			event.getApplicationContext().close();
		}
	}

	protected void loadJwks() throws Exception {
		remoteJWKSet.get(new JWKSelector(
						new JWKMatcher.Builder()
								.algorithm(JWSAlgorithm.RS256)
								.build()),
				null);
		log.info("Cached JWKS from {}", remoteJWKSet.getJWKSetURL());
	}

}
