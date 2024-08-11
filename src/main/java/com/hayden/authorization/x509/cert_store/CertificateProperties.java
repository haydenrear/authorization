package com.hayden.authorization.x509.cert_store;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Component;

import java.nio.file.Path;

@ConfigurationProperties(prefix = "x509")
@Component
@Data
public class CertificateProperties {

    private Path caCertificates;

    private CertificateStoreProperties certStore;

    private boolean enabled;

    @AllArgsConstructor
    @NoArgsConstructor
    @Data
    public static class CertificateStoreProperties {
        Path certStorePath;
        String certStorePassword;
        CertificateService.KeyStoreType keyStoreType;

        public CertificateService.KeyStoreArgs toArgs() {
            return CertificateService.KeyStoreArgs.builder()
                    .keystorePath(certStorePath)
                    .keystorePassword(certStorePassword.toCharArray())
                    .keyStoreType(keyStoreType)
                    .build();
        }
    }

}
