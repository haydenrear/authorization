package com.hayden.authorization.x509.model;

import com.hayden.persistence.models.JdbcAudited;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@EqualsAndHashCode(callSuper = true)
@Table(name ="x509_root")
@Entity(name = "x509_root")
@NoArgsConstructor
@AllArgsConstructor
@Data
public class X509RootCertificate extends JdbcAudited {

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
}
