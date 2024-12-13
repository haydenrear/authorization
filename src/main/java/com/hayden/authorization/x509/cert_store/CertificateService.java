package com.hayden.authorization.x509.cert_store;

import com.google.common.collect.Sets;
import com.hayden.authorization.x509.model.X509CertificateId;
import com.hayden.authorization.x509.model.X509RootCertificate;
import com.hayden.utilitymodule.result.agg.Agg;
import com.hayden.utilitymodule.result.agg.AggregateError;
import com.hayden.utilitymodule.result.agg.Responses;
import lombok.Builder;
import lombok.experimental.UtilityClass;
import com.hayden.utilitymodule.result.Result;
import com.hayden.utilitymodule.result.error.ErrorCollect;
import org.jetbrains.annotations.NotNull;

import java.io.*;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.hayden.authorization.x509.cert_store.ParseCertificateChain.parseCertificateChain;

@UtilityClass
public class CertificateService {


    public record CertificateParseError(String getMessage) implements ErrorCollect { }

    public record CertificateParseResult(List<X509Certificate> certificate) implements Responses.AggregateResponse {

        public CertificateParseResult(X509Certificate cert) {
            this(new ArrayList<>() {{ add(cert); }});
        }

        public CertificateParseResult() {
            this(new ArrayList<>());
        }

        @Override
        public void addAgg(Agg t) {
            if (t instanceof CertificateParseResult r) {
                this.certificate.addAll(r.certificate);
            }
        }
    }

    public record CertificateParseAggregateError(Set<ErrorCollect> errors) implements AggregateError.StdAggregateError {
        public CertificateParseAggregateError(String message) {
            this(new CertificateParseError(message));
        }

        public CertificateParseAggregateError(CertificateParseError error) {
            this(Sets.newHashSet(error));
        }
        public CertificateParseAggregateError() {
            this(new HashSet<>());
        }
    }

    @Builder
    public record KeyStoreArgs(Path keystorePath, char[] keystorePassword, KeyStoreType keyStoreType) {}

    public enum KeyStoreType {
        PKCS12, JKS
    }

    public Result<X509Certificate, CertificateParseError> loadCertificate(Path certificate) {
        return loadCertificateFromPem(certificate);
    }

    public static Result<X509CertificateId, CertificateParseAggregateError> removeCertificateToKeystore(KeyStoreArgs keyStoreArgs,
                                                                                                        X509CertificateId x509RootCertificate,
                                                                                                        String alias) {
        return doOnCertificateStore(keyStoreArgs, keystore -> {
                    try {
                        keystore.deleteEntry(alias);
                        return Result.ok(x509RootCertificate);
                    } catch (KeyStoreException e) {
                        return Result.err(new CertificateParseAggregateError("Error adding certificate to keystore with alias %s, subject %s, error message %s".formatted(alias, x509RootCertificate.getSubjectName(), e.getMessage())));
                    }
                });
    }

    public static Result<X509CertificateId, CertificateParseAggregateError> saveCertificateToKeystore(KeyStoreArgs keyStoreArgs,
                                                                                                      X509RootCertificate x509RootCertificate,
                                                                                                      String alias) {
        return x509RootCertificate.toCert()
                .mapError(CertificateParseAggregateError::new)
                .flatMapResult(x -> doOnCertificateStore(keyStoreArgs, keystore -> {
                    try {
                        keystore.setCertificateEntry(alias, x);
                        return Result.ok(new X509CertificateId(x));
                    } catch (KeyStoreException e) {
                        return Result.err(new CertificateParseAggregateError("Error adding certificate to keystore with alias %s, subject %s, error message %s".formatted(alias, x.getSubjectX500Principal().getName(), e.getMessage())));
                    }
                }));
    }

    public static Result<X509CertificateId, CertificateParseAggregateError> saveCertificateToDisk(Path caCertificatesDirectory, X509RootCertificate x509RootCertificate) {
        try(FileOutputStream fos = new FileOutputStream(caCertificatesDirectory.toFile())) {
            fos.write(x509RootCertificate.getCertificateValue());
            return Result.ok(x509RootCertificate.getUniqueId());
        } catch (IOException e) {
            return Result.err(new CertificateParseAggregateError("Failed to write certificate to file: %s".formatted(e.getMessage())));
        }
    }

    public static Result<X509CertificateId, CertificateParseAggregateError> removeCertificateToDisk(Path caCertificatesDirectory, X509CertificateId id) {
        try {
            if (caCertificatesDirectory.toFile().delete()) {
                return Result.ok(id);
            } else {
                return Result.err(new CertificateParseAggregateError("Certificate entry could not be deleted."));
            }
        } catch (SecurityException s) {
            return Result.err(new CertificateParseAggregateError("Could not delete - security manager responded: %s".formatted(s.getMessage())));
        }
    }

    public static Result<CertificateParseResult, CertificateParseAggregateError> loadCertificates(KeyStoreArgs keystore) {

        return doOnCertificateStore(keystore, keystoreLoaded -> {
            var aggregateError = new CertificateParseAggregateError();
            var certificateParseResult = new CertificateParseResult();

            Enumeration<String> aliases;
            try {
                aliases = keystoreLoaded.aliases();
            } catch (KeyStoreException e) {
                return Result.err(new CertificateParseAggregateError("Failed to load certificate aliases."));
            }

            while (aliases.hasMoreElements()) {
                try {
                    PKIXParameters pkixParams = retrievePKIXParameters(keystoreLoaded);
                    String alias = aliases.nextElement();
                    retrieveX509Certificate(keystoreLoaded, alias)
                            .ifPresentOrElse(
                                    x509Certificate -> parseX509CertificateAndChain(x509Certificate, pkixParams, certificateParseResult, aggregateError),
                                    () -> aggregateError.addAgg(new CertificateParseAggregateError("Unknown certificate type found in keystore for %s.".formatted(alias)))
                            );

                } catch (KeyStoreException |
                        InvalidAlgorithmParameterException e) {
                    aggregateError.addAgg(new CertificateParseAggregateError("Failed to parse cert %s.".formatted(e.getMessage())));
                }

            }

            return Result.from(certificateParseResult, aggregateError);
        });

    }


    public static <T> Result<T, CertificateParseAggregateError> doOnCertificateStore(KeyStoreArgs keystore,
                                                                                     Function<KeyStore, Result<T, CertificateParseAggregateError>> toDo) {
        if (!keystore.keystorePath.toFile().exists() || keystore.keystorePath.toFile().isDirectory()) {
            return Result.err(new CertificateParseAggregateError("Keystore path %s did not exist.".formatted(keystore.keystorePath.toString())));
        }

        var keystorePassword = keystore.keystorePassword;

        KeyStore keystoreLoaded;

        try {
            keystoreLoaded = KeyStore.getInstance(keystore.keyStoreType.name());
            try (FileInputStream fis = new FileInputStream(keystore.keystorePath.toFile())) {
                keystoreLoaded.load(fis, keystorePassword);
                return toDo.apply(keystoreLoaded);
            } catch (NoSuchAlgorithmException | CertificateException | IOException e) {
                return Result.err(new CertificateParseAggregateError("Failed to load keystore %s.".formatted(e.getMessage())));
            }
        } catch (KeyStoreException e) {
            return Result.err(new CertificateParseAggregateError("Failed to load keystore %s.".formatted(e.getMessage())));
        }
    }

    private static Optional<X509Certificate> retrieveX509Certificate(KeyStore keystoreLoaded, String alias) throws KeyStoreException {
        if (keystoreLoaded.isCertificateEntry(alias)
                && keystoreLoaded.getCertificate(alias) instanceof X509Certificate certificate)  {
            return Optional.of(certificate);
        }
        return Optional.empty();
    }

    private static void parseX509CertificateAndChain(X509Certificate x509Certificate, PKIXParameters pkixParams,
                                                     CertificateParseResult certificateParseResult,
                                                     CertificateParseAggregateError aggregateError)  {
        List<X509Certificate> certChain = new ArrayList<>();
        certChain.add(x509Certificate);


        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            CertPath certPath = certFactory.generateCertPath(certChain);
            CertPathValidator certPathValidator = CertPathValidator.getInstance("PKIX");
            CertPathValidatorResult result = certPathValidator.validate(certPath, pkixParams);

            TrustAnchor trustAnchor = ((PKIXCertPathValidatorResult) result).getTrustAnchor();
            X509Certificate rootCert = trustAnchor.getTrustedCert();

            var certChainFound = parseCertificateChain(rootCert);

            var isX509 = certPath.getCertificates()
                            .stream()
                            .collect(Collectors.partitioningBy(c -> c instanceof X509Certificate));

            certChainFound.ifPresent(certificateParseResult::addAgg);
            addCertsToResult(certificateParseResult, isX509.get(true));
            addErrorsToResult(aggregateError, isX509.get(false));

        } catch (CertPathValidatorException |
                 CertificateException |
                 NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException e) {
            aggregateError.addAgg(new CertificateParseAggregateError("Failed to parse cert: %s.".formatted(e.getMessage())));
        }
    }


    private static @NotNull PKIXParameters retrievePKIXParameters(KeyStore keystoreLoaded) throws KeyStoreException, InvalidAlgorithmParameterException {
        // Create a TrustAnchor set for PKIXParameters
        Set<TrustAnchor> trustAnchors = new HashSet<>();
        Enumeration<String> aliases = keystoreLoaded.aliases();

        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            retrieveX509Certificate(keystoreLoaded, alias)
                    .ifPresent(c -> trustAnchors.add(new TrustAnchor(c, null)));
        }

        PKIXParameters pkixParams = new PKIXParameters(trustAnchors);
        pkixParams.setRevocationEnabled(false);
        return pkixParams;
    }


    public static Result<X509Certificate, CertificateParseError> loadCertificateFromPem(Path filePath) {
        if (!filePath.toFile().exists() || filePath.toFile().isDirectory()) {
            return Result.err(new CertificateParseError("Path provided failed."));
        }
        try(
                FileInputStream fis = new FileInputStream(filePath.toFile());
                BufferedInputStream bis = new BufferedInputStream(fis);
        ) {
            return loadCertificateFromPemBytes(bis.readAllBytes());
        } catch (IOException e) {
            return Result.err(new CertificateParseError(e.getMessage()));
        }
    }

    public static Result<X509Certificate, CertificateService.CertificateParseError> loadCertificateFromPemBytes(byte[] certificateValue) {
        try {
            var c = CertificateFactory.getInstance("X509");
            var x = c.generateCertificate(new ByteArrayInputStream(certificateValue));
            if (x instanceof X509Certificate x509) {
                return Result.ok(x509);
            }

            return Result.err(new CertificateService.CertificateParseError("Found unknown certificate parse: %s."
                    .formatted(x.getClass().getName())));
        } catch (CertificateException e) {
            return Result.err(new CertificateService.CertificateParseError("Could not find certificate factory: %s"
                    .formatted(e.getMessage())));
        }
    }


    private static void addErrorsToResult(CertificateParseAggregateError aggregateError, List<? extends Certificate> value) {
        Optional.ofNullable(value)
                .stream()
                .flatMap(Collection::stream)
                .flatMap(c -> c instanceof X509Certificate ? Stream.empty() : Stream.of(c))
                .map(c -> new CertificateParseAggregateError("Unknown certificate found: %s.".formatted(c)))
                .forEach(aggregateError::addAgg);
    }

    private static void addCertsToResult(CertificateParseResult certificateParseResult,
                                         List<? extends Certificate> value) {
        var x509 = Optional.ofNullable(value)
                .stream()
                .flatMap(Collection::stream)
                .flatMap(c -> c instanceof X509Certificate x ? Stream.of(x) : Stream.empty())
                .toList();

        certificateParseResult.addAgg(new CertificateParseResult(x509));
    }



}
