package com.hayden.authorization.x509.model;

import com.hayden.persistence.models.JdbcAudited;
import jakarta.persistence.*;
import lombok.*;

@EqualsAndHashCode(callSuper = true)
@Table(name = "x509_cert")
@Entity(name = "x509_cert")
@NoArgsConstructor
@AllArgsConstructor
@Data
public class TrustedUserX509Certificate extends JdbcAudited {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long id;

    @Column(name = "certificate_value")
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    byte[] certificateValue;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "root_certificate_id", referencedColumnName = "id")
    @EqualsAndHashCode.Exclude
    @ToString.Exclude
    private X509RootCertificate rootCertificates;

    @Embedded
    X509CertificateId uniqueId;
}
