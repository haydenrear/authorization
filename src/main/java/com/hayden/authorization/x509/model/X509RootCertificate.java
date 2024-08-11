package com.hayden.authorization.x509.model;
import com.hayden.authorization.x509.cert_store.CertificateService;
import com.hayden.persistence.models.Audited;
import com.hayden.utilitymodule.result.Result;
import jakarta.persistence.*;
import lombok.*;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Table(name ="x509_root")
@Entity(name = "x509_root")
@NoArgsConstructor
@AllArgsConstructor
@Data
public class X509RootCertificate extends Audited {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    long id;

    @Column(name="certificate_value")
    byte[] certificateValue;

    @OneToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "x509_cert_link", // Name of the join table
            joinColumns = @JoinColumn(name = "root_cert_id"), // Foreign key for RootCaCertificate
            inverseJoinColumns = @JoinColumn(name = "user_certificate_id") // Foreign key for TrustedUserX509Certificate
    )
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    List<TrustedUserX509Certificate> certificateLink;

    @Embedded
    X509CertificateId uniqueId;

    public void addTrustedCaCert(TrustedUserX509Certificate userX509Certificate) {
        if (certificateLink == null) {
            certificateLink = new ArrayList<>();
        }
        certificateLink.add(userX509Certificate);
    }

    public Result<X509Certificate, CertificateService.CertificateParseError> toCert() {
        return CertificateService.loadCertificateFromPemBytes(this.certificateValue);
    }

}
