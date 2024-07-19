package com.hayden.authorization.x509.repository;

import com.hayden.authorization.x509.model.QX509RootCertificate;
import com.hayden.authorization.x509.model.TrustedUserX509Certificate;
import com.hayden.authorization.x509.model.X509RootCertificate;
import com.querydsl.jpa.impl.JPAQueryFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;


@SpringBootTest
@ExtendWith(SpringExtension.class)
@ActiveProfiles("h2")
public class TrustedCaCertificateRepoTest {

    @Autowired
    RootCaCertificateRepository rootCaCertificateRepository;
    @Autowired
    TrustedCaCertificateRepo caCertificateRepo;
    @Autowired
    JPAQueryFactory queryFactory;

    @Test
    public void testAddRemove() {
        X509RootCertificate rootCert = new X509RootCertificate();
        rootCert.setCertificateValue(new byte[]{});
        rootCert = rootCaCertificateRepository.save(rootCert);
        assertThat(rootCert.getId()).isNotNull();
        var found = queryFactory.selectFrom(QX509RootCertificate.x509RootCertificate)
                .select(QX509RootCertificate.x509RootCertificate)
                .fetch()
                .size();
        assertThat(found).isNotZero();
        X509RootCertificate finalEntity = rootCert;
        var fromRepo = rootCaCertificateRepository.findAll().stream().filter(x -> x.getId() == finalEntity.getId())
                .findAny();
        assertThat(fromRepo).isPresent();

        TrustedUserX509Certificate userX509Certificate = new TrustedUserX509Certificate();
        userX509Certificate.setRootCertificates(rootCert);
        userX509Certificate.setCertificateValue(new byte[] {});
        userX509Certificate = caCertificateRepo.save(userX509Certificate);
        rootCert.addTrustedCaCert(userX509Certificate);
        rootCert = rootCaCertificateRepository.save(rootCert);

        assertThat(rootCert.getCertificateLink().stream().allMatch(t -> t.getId() != null)).isTrue();
    }

}