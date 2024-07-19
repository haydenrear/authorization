package com.hayden.authorization.x509;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;

import java.security.cert.X509Certificate;
import java.util.Optional;

@UtilityClass
public class X509AuthenticationGrantType {


    public static final String X_509 = "X509";


    public static Optional<X509Certificate> extractCert(HttpServletRequest request) {
        return Optional.empty();
    }
}
