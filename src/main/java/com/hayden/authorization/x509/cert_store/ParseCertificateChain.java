package com.hayden.authorization.x509.cert_store;

import com.hayden.utilitymodule.result.Result;
import com.hayden.utilitymodule.result.map.ResultCollectors;
import lombok.experimental.UtilityClass;
import org.apache.commons.compress.utils.Lists;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@UtilityClass
public class ParseCertificateChain {


    static Result<CertificateService.CertificateParseResult, CertificateService.CertificateParseAggregateError> parseCertificateChain(X509Certificate certificate){
        List<X509Certificate> certChain = new ArrayList<>();
        certChain.add(certificate);

        Result<CertificateService.CertificateParseResult, CertificateService.CertificateParseAggregateError> next;

        while ((next = getIssuerCertificate(certificate)).isOk()) {
            if (next.r().isPresent() && !next.r().get().certificate().isEmpty())  {
                certChain.addAll(next.r().get().certificate());
            } else {
                break;
            }
        }

        var certErr = new CertificateService.CertificateParseAggregateError();

        if (next.isError()) {
            certErr.add(next.e().get());
        }

        return Result.from(new CertificateService.CertificateParseResult(certChain), certErr);
    }

    static Result<CertificateService.CertificateParseResult, CertificateService.CertificateParseAggregateError> getIssuerCertificate(X509Certificate certificate) {
        return retrieveAiaExtensionIfExists(certificate)
                .orElseRes(Optional.empty())
                .map(ASN1Sequence::iterator)
                .map(Lists::newArrayList)
                .orElse(new ArrayList<>())
                .stream()
                .<Result<CertificateService.CertificateParseResult, CertificateService.CertificateParseAggregateError>>map(asn1Encodable -> {
                    if (asn1Encodable instanceof ASN1Sequence accessDescription) {
                        return getCaIssuerUrlOctet(accessDescription)
                                .flatMapResult(accessLocationBytes -> {
                                    String urlString = new String(accessLocationBytes);
                                    return getNextCertChainFromUrl(urlString);
                                });
                    } else {
                        return Result.err(new CertificateService.CertificateParseAggregateError("Could not parse encodable of type: %s.".formatted(asn1Encodable.getClass().getName())));
                    }
                })
                .collect(ResultCollectors.from(
                        new CertificateService.CertificateParseResult(),
                        new CertificateService.CertificateParseAggregateError()
                ));
    }

    public static Result<Optional<ASN1Sequence>, CertificateService.CertificateParseAggregateError> retrieveAiaExtensionIfExists(X509Certificate certificate) {
        byte[] aiaExtensionValue = certificate.getExtensionValue("1.3.6.1.5.5.7.1.1");
        if (aiaExtensionValue == null) {
            return Result.ok(Optional.empty());
        }

        ASN1Primitive asn1Sequence;
        try {
            asn1Sequence = JcaX509ExtensionUtils.parseExtensionValue(aiaExtensionValue);
        } catch (IOException e) {
            return Result.err(new CertificateService.CertificateParseAggregateError("Error parsing asn1 extension value %s, %s".formatted(aiaExtensionValue, e.getMessage())));
        }

        if (!(asn1Sequence instanceof ASN1Sequence aiaSequence)) {
            return Result.err(new CertificateService.CertificateParseAggregateError("Could not parse aid certificate extension of type %s."
                    .formatted(asn1Sequence.getClass().getName())));
        } else {
            return Result.ok(Optional.of(aiaSequence));
        }
    }

    public static Result<byte[], CertificateService.CertificateParseAggregateError> getCaIssuerUrlOctet(ASN1Sequence accessDescription) {
        if (accessDescription.size() != 2) {
            return Result.err(new CertificateService.CertificateParseAggregateError("Could not parse access description: %s.".formatted(Arrays.toString(accessDescription.toArray()))));
        }

        ASN1ObjectIdentifier accessMethod = (ASN1ObjectIdentifier) accessDescription.getObjectAt(0);
        if (!accessMethod.equals(X509ObjectIdentifiers.id_ad_caIssuers) && !accessMethod.equals(X509ObjectIdentifiers.id_ad_ocsp)) {
            return Result.err(new CertificateService.CertificateParseAggregateError("Unrecognized access method: %s.".formatted(accessMethod)));
        }

        ASN1TaggedObject objectAt1 = (ASN1TaggedObject) accessDescription.getObjectAt(1);
        ASN1OctetString accessLocation = (DEROctetString) objectAt1.getBaseObject();
        return Result.ok(accessLocation.getOctets());
    }

    private static Result<CertificateService.CertificateParseResult, CertificateService.CertificateParseAggregateError> getNextCertChainFromUrl(String urlString) {
        try (InputStream in = URI.create(urlString).toURL().openStream()) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Certificate result = cf.generateCertificate(in);

            if (result instanceof X509Certificate x509Certificate) {
                return Result.ok(new CertificateService.CertificateParseResult(x509Certificate));
            }

            return Result.err(new CertificateService.CertificateParseAggregateError("Found unknown cert type: %s.".formatted(result.getClass().getName())));
        } catch (CertificateException | IOException e) {
            return Result.err(new CertificateService.CertificateParseAggregateError("Failed to load cert: %s.".formatted(e.getMessage())));
        }
    }

}
