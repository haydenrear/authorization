package com.hayden.authorization.x509.model;

import jakarta.persistence.Embeddable;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Objects;

@Embeddable
@AllArgsConstructor
@NoArgsConstructor
@Data
public final class X509CertificateId {
    private String subjectName;
    private String issuerName;
    private String serialNumber;
}
