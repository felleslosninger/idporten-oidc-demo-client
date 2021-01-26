package no.digdir.oidc.testclient.service;

import com.nimbusds.jose.util.DefaultResourceRetriever;
import com.nimbusds.jose.util.Resource;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URL;

@Slf4j
public class LoggingResourceRetriever extends DefaultResourceRetriever {

    public LoggingResourceRetriever(int connectTimeout, int readTimeout) {
        super(connectTimeout, readTimeout);
    }

    @Override
    public Resource retrieveResource(URL url) throws IOException {
        try {
            Resource resource = super.retrieveResource(url);
            if (log.isInfoEnabled()) {
                log.info("Loaded resource from {}", url);
            }
            return resource;
        } catch (IOException e) {
            log.info("Failed to load resource from {}", url, e);
            throw e;
        }
    }

}
