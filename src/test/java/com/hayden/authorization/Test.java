package com.hayden.authorization;

import com.hayden.authorization.x509.model.X509CertificateId;
import lombok.SneakyThrows;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.net.URL;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.*;
import java.util.*;

public class Test {

    static {
        // Register BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        try {
            // Load the keystore (e.g., from the default JDK location)
            var cert = loadCertificateFromPem("authorization/src/main/resources/chatgpt.com.pem");
            var certChain1 = getCertificateChain(cert);
            String keystorePath = System.getProperty("java.home") + "/lib/security/cacerts";
            char[] keystorePassword = "changeit".toCharArray();  // Default password

            KeyStore keystore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(keystorePath)) {
                keystore.load(fis, keystorePassword);
            }

            // Create a TrustAnchor set for PKIXParameters
            Set<TrustAnchor> trustAnchors = new HashSet<>();
            Enumeration<String> aliases = keystore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keystore.getCertificate(alias);
                if (certificate instanceof X509Certificate) {
                    trustAnchors.add(new TrustAnchor((X509Certificate) certificate, null));
                }
            }

            PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
            pkixParams.setRevocationEnabled(false);

            // Reset aliases to iterate again for certificate processing
            aliases = keystore.aliases();

            // Iterate through the keystore entries
            List<X509CertificateId> certificateIds = new ArrayList<>();

            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keystore.getCertificate(alias);

                if (certificate instanceof X509Certificate) {
                    X509Certificate x509Certificate = (X509Certificate) certificate;
                    String issuerName = x509Certificate.getIssuerX500Principal().getName();
                    String serialNumber = x509Certificate.getSerialNumber().toString();

//                    X509CertificateId certificateId = new X509CertificateId(issuerName, serialNumber);
//                    certificateIds.add(certificateId);

                    // Build certificate chain
                    List<X509Certificate> certChain = new ArrayList<>();
                    certChain.add(x509Certificate);

                    // Validate the certificate path
                    CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
                    CertPath certPath = certFactory.generateCertPath(certChain);
                    CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
                    try {
                        CertPathValidatorResult result = certPathValidator.validate(certPath, pkixParams);

                        // Extract the root certificate (TrustAnchor)
                        TrustAnchor trustAnchor = ((PKIXCertPathValidatorResult) result).getTrustAnchor();
                        X509Certificate rootCert = trustAnchor.getTrustedCert();

                        var certChainFound = getCertificateChain(rootCert);

                        if (rootCert != null) {
                            String rootIssuerName = rootCert.getIssuerX500Principal().getName();
                            String rootSerialNumber = rootCert.getSerialNumber().toString();
//                        X509CertificateId rootCertId = new X509CertificateId(rootIssuerName, rootSerialNumber);
//                        certificateIds.add(rootCertId);
                        }
                    } catch (CertPathValidatorException e) {
                        e.printStackTrace();
                    }

                }
            }

            // Print out the collected certificate IDs
            for (X509CertificateId certificateId : certificateIds) {
                System.out.println(certificateId);
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
    }


    @SneakyThrows
    private static void saveCertificateToPem(X509Certificate certificate, String filePath) throws IOException {
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getEncoder().encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----\n";

        try (FileWriter fileWriter = new FileWriter(filePath)) {
            fileWriter.write(pem);
        }
    }

}
