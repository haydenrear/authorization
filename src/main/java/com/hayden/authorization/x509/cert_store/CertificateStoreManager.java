package com.hayden.authorization.x509.cert_store;

import com.google.common.collect.Sets;
import com.hayden.authorization.x509.model.QX509RootCertificate;
import com.hayden.authorization.x509.model.X509CertificateId;
import com.hayden.authorization.x509.model.X509RootCertificate;
import com.hayden.authorization.x509.repository.RootCaCertificateRepository;
import com.hayden.utilitymodule.io.FileUtils;
import com.hayden.utilitymodule.result.Result;
import com.hayden.utilitymodule.result.map.ResultCollectors;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.web.embedded.TomcatVirtualThreadsWebServerFactoryCustomizer;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.stereotype.Component;

import java.io.File;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
@Slf4j
public class CertificateStoreManager {

    private final RootCaCertificateRepository rootCaCertificateRepository;
    private final CertificateProperties certificateProperties;
//    private final TomcatVirtualThreadsWebServerFactoryCustomizer tomcatVirtualThreadsProtocolHandlerCustomizer;

    public sealed interface ToSave permits ToSave.ToSaveInStore, ToSave.ToSaveOnDisk, ToSave.ToRemoveFromDisk, ToSave.ToRemoveFromStore {

        record ToSaveInStore(X509CertificateId certificateId) implements ToSave {}

        record ToSaveOnDisk(X509CertificateId certificateId) implements ToSave {}

        record ToRemoveFromDisk(X509CertificateId certificateId) implements ToSave {}

        record ToRemoveFromStore(X509CertificateId certificateId) implements ToSave {}

    }

    @PostConstruct
    public void syncCertsOnStartup() {
        if (!certificateProperties.isEnabled())
            return;

        log.info("Syncing certificates on load.");
        // TODO what is necessary to ensure that Tomcat doesn't need to be restarted? Is federated controller the only way?
        syncCerts();
        log.info("Finished syncing certificates on load.");
    }

    public void syncCerts() {
        toSave().forEach(t -> {
            switch (t) {
                case ToSave.ToSaveOnDisk s ->
                        rootCaCertificateRepository.findX509RootCertificateByUniqueId(s.certificateId)
                                .ifPresent(x -> CertificateService.saveCertificateToDisk(certificateProperties.getCaCertificates(), x));
                case ToSave.ToSaveInStore s ->
                        rootCaCertificateRepository.findX509RootCertificateByUniqueId(s.certificateId)
                                .ifPresent(x -> CertificateService.saveCertificateToKeystore(certificateProperties.getCertStore().toArgs(), x, s.certificateId.getSubjectName()));
                case ToSave.ToRemoveFromStore s ->
                        CertificateService.removeCertificateToKeystore(certificateProperties.getCertStore().toArgs(), s.certificateId, s.certificateId.getSubjectName());
                case ToSave.ToRemoveFromDisk s ->
                        CertificateService.removeCertificateToDisk(certificateProperties.getCaCertificates(), s.certificateId);
            }
        });
    }

    /**
     * source of truth
     * @return
     */
    Set<X509CertificateId> retrieveCurrentInDatabase() {
        return rootCaCertificateRepository.findAll()
                .stream()
                .map(X509RootCertificate::getUniqueId)
                .collect(Collectors.toSet());
    }

    Set<X509CertificateId> retrieveCurrentInStore() {
        return CertificateService.loadCertificates(certificateProperties.getCertStore().toArgs())
                .flatMapStreamResult(c -> c.certificate().stream()
                        .map(X509CertificateId::new)
                        .map(Result::ok)
                )
                // TODO: propagate error
                .flatMap(r -> r.one().stream())
                .collect(Collectors.toSet());
    }

    Set<X509CertificateId> retrieveCurrentOnDisk() {
        return FileUtils.getFileStream(certificateProperties.getCaCertificates())
                .map(File::toPath)
                .map(p -> Result.<Path, CertificateService.CertificateParseError>ok(p)
                        .flatMapResult(CertificateService::loadCertificateFromPem)
                        .map(X509CertificateId::new)
                        .doOnError(e -> {})
                )
                // TODO: propagate error
                .flatMap(s -> s.one().stream())
                .collect(Collectors.toSet());
    }

    /**
     * In order for x509 client certificate auth to work the cert must be added to the ca-certificates directory
     * and also must also exist in the trusted ca-certs keystore for tomcat.
     * @return Set of items to save.
     */
    Set<ToSave> toSave() {
        var curr = retrieveCurrentInDatabase();
        var inStore = retrieveCurrentInStore();
        var onDisk = retrieveCurrentOnDisk();

        var toSaveInStore = Sets.difference(curr, inStore);
        var toSaveOnDisk = Sets.difference(curr, onDisk);

        var toRemoveFromStore = Sets.difference(inStore, curr);
        var toRemoveFromDisk = Sets.difference(onDisk, curr);

        var toSave = new HashSet<ToSave>();

        toSaveInStore.stream()
                .map(ToSave.ToSaveInStore::new)
                .forEach(toSave::add);
        toSaveOnDisk.stream()
                .map(ToSave.ToSaveOnDisk::new)
                .forEach(toSave::add);
        toRemoveFromDisk.stream()
                .map(ToSave.ToRemoveFromDisk::new)
                .forEach(toSave::add);
        toRemoveFromStore.stream()
                .map(ToSave.ToRemoveFromStore::new)
                .forEach(toSave::add);

        return toSave;

    }

}
