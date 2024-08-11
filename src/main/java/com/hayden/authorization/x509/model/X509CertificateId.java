package com.hayden.authorization.x509.model;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.Objects;

@Embeddable
@AllArgsConstructor
@NoArgsConstructor
@Data
public final class X509CertificateId {
    private String subjectName;
    private String issuerName;
    private String serialNumber;

    public X509CertificateId(X509Certificate x509Certificate) {
        this(x509Certificate.getSubjectX500Principal().getName(),
                x509Certificate.getIssuerX500Principal().getName(),
                x509Certificate.getSerialNumber().toString());
    }

}
