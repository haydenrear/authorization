package com.hayden.authorization.x509;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

import java.security.cert.X509Certificate;
import java.util.Optional;

@UtilityClass
public class X509AuthenticationGrantType {


    public static final AuthorizationGrantType X_509 = new AuthorizationGrantType("X509");
    public static final String X_509_ATTRIBUTE = "javax.servlet.request.X509Certificate";


    public static Optional<X509Certificate> extractCert(HttpServletRequest request) {
        X509Certificate[] certs = (X509Certificate[]) request.getAttribute(X_509_ATTRIBUTE);
        return Optional.ofNullable(certs)
                .filter(c -> c.length != 0)
                .map(c -> c[0]);
    }
}
