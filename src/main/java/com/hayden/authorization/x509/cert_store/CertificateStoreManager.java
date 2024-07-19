package com.hayden.authorization.x509.cert_store;

import com.google.common.collect.Sets;
import com.hayden.authorization.x509.model.X509CertificateId;
import com.hayden.authorization.x509.model.X509RootCertificate;
import com.hayden.authorization.x509.repository.RootCaCertificateRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

@Component
@RequiredArgsConstructor
public class CertificateStoreManager {

    private final RootCaCertificateRepository rootCaCertificateRepository;

    /**
     * source of truth
     * @return
     */
    Set<X509CertificateId> retrieveCurrentInDatabase() {
        return rootCaCertificateRepository.findAll()
                .stream().map(X509RootCertificate::getUniqueId)
                .collect(Collectors.toSet());
    }

    Set<X509CertificateId> retrieveCurrentInStore() {
        return new HashSet<>() ;
    }

    Set<X509CertificateId> retrieveCurrentOnDisk() {
        return new HashSet<>();
    }

    public interface ToSave {

        record ToSaveInStore(X509CertificateId certificateId) implements ToSave {}
        record ToSaveOnDisk(X509CertificateId certificateId) implements ToSave {}
    }

    Set<ToSave> toSave() {
        var curr = retrieveCurrentInDatabase();
        var inStore = retrieveCurrentInStore();
        var onDisk = retrieveCurrentOnDisk();

        var toSaveInStore = Sets.difference(curr, inStore);
        var toSaveOnDisk = Sets.difference(curr, onDisk);

        var toSave = new HashSet<ToSave>();

        toSaveInStore.stream()
                .map(ToSave.ToSaveInStore::new)
                .forEach(toSave::add);
        toSaveOnDisk.stream()
                .map(ToSave.ToSaveOnDisk::new)
                .forEach(toSave::add);

        return toSave;

    }

}
