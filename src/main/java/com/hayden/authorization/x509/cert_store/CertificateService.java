package com.hayden.authorization.x509.cert_store;

import com.google.common.collect.Sets;
import com.hayden.utilitymodule.result.Agg;
import com.hayden.utilitymodule.result.error.AggregateError;
import com.hayden.utilitymodule.result.map.ResultCollectors;
import com.hayden.utilitymodule.result.res.Responses;
import org.apache.commons.compress.utils.Lists;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import com.hayden.utilitymodule.result.Result;
import com.hayden.utilitymodule.result.error.Error;
import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Service;

import java.io.*;
import java.net.URI;
import java.nio.file.Path;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Service
public class CertificateService {


    public record CertificateParseError(String getMessage) implements Error { }

    public record CertificateParseResult(List<X509Certificate> certificate) implements Responses.AggregateResponse {

        public CertificateParseResult(X509Certificate cert) {
            this(new ArrayList<>() {{ add(cert); }});
        }

        public CertificateParseResult() {
            this(new ArrayList<>());
        }

        @Override
        public void add(Agg t) {
            if (t instanceof CertificateParseResult r) {
                this.certificate.addAll(r.certificate);
            }
        }
    }

    public record CertificateParseAggregateError(Set<Error> errors) implements AggregateError {
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

    public record KeyStoreArgs(Path keystorePath, char[] keystorePassword, KeyStoreType keyStoreType) {}

    public enum KeyStoreType {
        PKCS12, JKS
    }

    public Result<X509Certificate, CertificateParseError> loadCertificate(Path certificate) {
        return loadCertificateFromPem(certificate);
    }

    public Result<CertificateParseResult, CertificateParseAggregateError> loadCertificates(KeyStoreArgs keystore) {

        if (!keystore.keystorePath.toFile().exists() || keystore.keystorePath.toFile().isDirectory()) {
            return Result.err(new CertificateParseAggregateError("Keystore path %s did not exist.".formatted(keystore.keystorePath.toString())));
        }

        var keystorePassword = keystore.keystorePassword;

        KeyStore keystoreLoaded;

        try {
            keystoreLoaded = KeyStore.getInstance(keystore.keyStoreType.name());
        } catch (KeyStoreException e) {
            return Result.err(new CertificateParseAggregateError("Failed to load keystore %s.".formatted(e.getMessage())));
        }

        var aggregateError = new CertificateParseAggregateError();
        var certificateParseResult = new CertificateParseResult();

        try (FileInputStream fis = new FileInputStream(keystore.keystorePath.toFile())) {
            keystoreLoaded.load(fis, keystorePassword);

            Enumeration<String> aliases = keystoreLoaded.aliases();

            while (aliases.hasMoreElements()) {
                try {

                    PKIXParameters pkixParams = retrievePKIXParameters(keystoreLoaded);
                    String alias = aliases.nextElement();
                    retrieveX509Certificate(keystoreLoaded, alias)
                            .ifPresentOrElse(
                                    x509Certificate -> parseX509CertificateAndChain(x509Certificate, pkixParams, certificateParseResult, aggregateError),
                                    () -> aggregateError.add(new CertificateParseAggregateError("Unknown certificate type found in keystore for %s.".formatted(alias)))
                            );

                } catch (
                        KeyStoreException |
                        InvalidAlgorithmParameterException e) {
                    aggregateError.add(new CertificateParseAggregateError("Failed to parse cert %s.".formatted(e.getMessage())));
                }

            }
        } catch (IOException |
                 NoSuchAlgorithmException |
                 CertificateException |
                 KeyStoreException e) {
            aggregateError.add(new CertificateParseAggregateError("Failed to load keystore %s.".formatted(e.getMessage())));
        }


        return Result.from(certificateParseResult, aggregateError);
    }

    private static Optional<X509Certificate> retrieveX509Certificate(KeyStore keystoreLoaded, String alias) throws KeyStoreException {
        if (keystoreLoaded.getCertificate(alias) instanceof X509Certificate certificate)  {
            return Optional.of(certificate);
        }
        return Optional.empty();
    }

    private static void parseX509CertificateAndChain(X509Certificate x509Certificate, PKIXParameters pkixParams, CertificateParseResult certificateParseResult, CertificateParseAggregateError aggregateError)  {
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

            certChainFound.ifPresent(certificateParseResult::add);
            addCertsToResult(certificateParseResult, isX509.get(true));
            addErrorsToResult(aggregateError, isX509.get(false));

        } catch (CertPathValidatorException |
                 CertificateException |
                 NoSuchAlgorithmException |
                 InvalidAlgorithmParameterException e) {
            aggregateError.add(new CertificateParseAggregateError("Failed to parse cert: %s.".formatted(e.getMessage())));
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

    static Result<CertificateParseResult, CertificateParseAggregateError> parseCertificateChain(X509Certificate certificate){
        List<X509Certificate> certChain = new ArrayList<>();
        certChain.add(certificate);

        Result<CertificateParseResult, CertificateService.CertificateParseAggregateError> next;

        while ((next = getIssuerCertificate(certificate)).isOk()) {
            if (next.isPresent() && !next.get().certificate().isEmpty())  {
                certChain.addAll(next.get().certificate);
            } else {
                break;
            }
        }

        var certErr = new CertificateParseAggregateError();

        if (next.isError()) {
            certErr.add(next.error());
        }

        return Result.from(new CertificateParseResult(certChain), certErr);
    }

    static Result<X509Certificate, CertificateParseError> loadCertificateFromPem(Path filePath) {
        if (!filePath.toFile().exists() || filePath.toFile().isDirectory()) {
            return Result.err(new CertificateParseError("Path provided failed."));
        }
        try(
                FileInputStream fis = new FileInputStream(filePath.toFile());
                BufferedInputStream bis = new BufferedInputStream(fis);
        ) {
            Certificate parsedCert = CertificateFactory.getInstance("X.509").generateCertificate(bis);
            if (parsedCert instanceof X509Certificate certificate) {
                return Result.ok(certificate);
            }

            return Result.err(new CertificateParseError("Unknown certificate type: %s.".formatted(parsedCert.getClass().getName())));
        } catch (CertificateException |
                 IOException e) {
            return Result.err(new CertificateParseError(e.getMessage()));
        }

    }

    private static void addErrorsToResult(CertificateParseAggregateError aggregateError, List<? extends Certificate> value) {
        Optional.ofNullable(value)
                .stream()
                .flatMap(Collection::stream)
                .flatMap(c -> c instanceof X509Certificate ? Stream.empty() : Stream.of(c))
                .map(c -> new CertificateParseAggregateError("Unknown certificate found: %s.".formatted(c)))
                .forEach(aggregateError::add);
    }

    private static void addCertsToResult(CertificateParseResult certificateParseResult,
                                         List<? extends Certificate> value) {
        var x509 = Optional.ofNullable(value)
                .stream()
                .flatMap(Collection::stream)
                .flatMap(c -> c instanceof X509Certificate x ? Stream.of(x) : Stream.empty())
                .toList();

        certificateParseResult.add(new CertificateParseResult(x509));
    }

    static Result<CertificateParseResult, CertificateService.CertificateParseAggregateError> getIssuerCertificate(X509Certificate certificate) {
        return retrieveAiaExtensionIfExists(certificate)
                .orElse(Optional.empty())
                .map(ASN1Sequence::iterator)
                .map(Lists::newArrayList)
                .orElse(new ArrayList<>())
                .stream()
                .<Result<CertificateParseResult, CertificateParseAggregateError>>map(asn1Encodable -> {
                    if (asn1Encodable instanceof ASN1Sequence accessDescription) {
                        return getCaIssuerUrlOctet(accessDescription)
                                .flatMapResult(accessLocationBytes -> {
                                    String urlString = new String(accessLocationBytes);
                                    return getNextCertChainFromUrl(urlString);
                                });
                    } else {
                        return Result.err(new CertificateParseAggregateError("Could not parse encodable of type: %s.".formatted(asn1Encodable.getClass().getName())));
                    }
                })
                .collect(ResultCollectors.from(
                        new CertificateParseResult(),
                        new CertificateParseAggregateError()
                ));
    }

    public static Result<Optional<ASN1Sequence>, CertificateParseAggregateError> retrieveAiaExtensionIfExists(X509Certificate certificate) {
        byte[] aiaExtensionValue = certificate.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (aiaExtensionValue == null) {
            return Result.ok(Optional.empty());
        }

        ASN1Primitive asn1Sequence;
        try {
            asn1Sequence = JcaX509ExtensionUtils.parseExtensionValue(aiaExtensionValue);
        } catch (IOException e) {
            return Result.err(new CertificateParseAggregateError("Error parsing asn1 extension value %s, %s".formatted(aiaExtensionValue, e.getMessage())));
        }

        if (!(asn1Sequence instanceof ASN1Sequence aiaSequence)) {
            return Result.err(new CertificateParseAggregateError("Could not parse aid certificate extension of type %s."
                    .formatted(asn1Sequence.getClass().getName())));
        } else {
            return Result.ok(Optional.of(aiaSequence));
        }
    }

    public static Result<byte[], CertificateParseAggregateError> getCaIssuerUrlOctet(ASN1Sequence accessDescription) {
        if (accessDescription.size() != 2) {
            return Result.err(new CertificateParseAggregateError("Could not parse access description: %s.".formatted(Arrays.toString(accessDescription.toArray()))));
        }

        ASN1ObjectIdentifier accessMethod = (ASN1ObjectIdentifier) accessDescription.getObjectAt(0);
        if (!accessMethod.equals(X509ObjectIdentifiers.id_ad_caIssuers) && !accessMethod.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
            return Result.err(new CertificateParseAggregateError("Unrecognized access method: %s.".formatted(accessMethod)));
        }

        ASN1TaggedObject objectAt1 = (ASN1TaggedObject) accessDescription.getObjectAt(1);
        ASN1OctetString accessLocation = (DEROctetString) objectAt1.getBaseObject();
        return Result.ok(accessLocation.getOctets());
    }

    private static Result<CertificateParseResult, CertificateParseAggregateError> getNextCertChainFromUrl(String urlString) {
        try (InputStream in = URI.create(urlString).toURL().openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate result = cf.generateCertificate(in);

            if (result instanceof X509Certificate x509Certificate) {
                return Result.ok(new CertificateParseResult(x509Certificate));
            }

            return Result.err(new CertificateParseAggregateError("Found unknown cert type: %s.".formatted(result.getClass().getName())));
        } catch (CertificateException | IOException e) {
            return Result.err(new CertificateParseAggregateError("Failed to load cert: %s.".formatted(e.getMessage())));
        }
    }


}
