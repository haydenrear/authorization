package com.hayden.authorization.oidc;

import com.hayden.authorization.config.AuthorizationServerConfigProps;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.hayden.authorization.user.QCdcUser;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.function.Function;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class UserEndpointUserInfoMapper implements Function<OidcUserInfoAuthenticationContext, OidcUserInfo> {



    // @formatter:off
    private static final List<String> EMAIL_CLAIMS = Arrays.asList(
            StandardClaimNames.EMAIL,
            StandardClaimNames.EMAIL_VERIFIED
    );
    private static final List<String> PHONE_CLAIMS = Arrays.asList(
            StandardClaimNames.PHONE_NUMBER,
            StandardClaimNames.PHONE_NUMBER_VERIFIED
    );
    private static final List<String> PROFILE_CLAIMS = Arrays.asList(
            StandardClaimNames.NAME,
            StandardClaimNames.FAMILY_NAME,
            StandardClaimNames.GIVEN_NAME,
            StandardClaimNames.MIDDLE_NAME,
            StandardClaimNames.NICKNAME,
            StandardClaimNames.PREFERRED_USERNAME,
            StandardClaimNames.PROFILE,
            StandardClaimNames.PICTURE,
            StandardClaimNames.WEBSITE,
            StandardClaimNames.GENDER,
            StandardClaimNames.BIRTHDATE,
            StandardClaimNames.ZONEINFO,
            StandardClaimNames.LOCALE,
            StandardClaimNames.UPDATED_AT
    );
    // @formatter:on

    private final CdcUserRepository userRepository;

    private final AuthorizationServerConfigProps configProps;

    @Override
    public OidcUserInfo apply(OidcUserInfoAuthenticationContext oidcUserInfoAuthenticationContext) {
        var claims = getUserInfoDefault(oidcUserInfoAuthenticationContext);

        var defaultValue = new OidcUserInfo(claims);

        if (oidcUserInfoAuthenticationContext.getAuthentication() instanceof OidcUserInfoAuthenticationToken oidcToken
            && oidcToken.getCredentials() instanceof Jwt jwt) {
            claims.putAll(jwt.getClaims());
            return new OidcUserInfo(claims);
        }

        var emailFound = defaultValue.getEmail();
        var fullName = defaultValue.getFullName();
        var givenName = defaultValue.getGivenName();
        var nickName = defaultValue.getNickName();


//        var b = QCdcUser.cdcUser.email.eq(emailFound)
//                .or(QCdcUser.cdcUser.principalId.principalId.eq(emailFound));
//
//        for (var n : List.of(fullName, givenName, nickName)) {
//            b = b.or(QCdcUser.cdcUser.email.eq(n))
//                    .or(QCdcUser.cdcUser.principalId.principalId.eq(n));
//        }

        return defaultValue;

    }



    public Map<String, Object> getUserInfoDefault(OidcUserInfoAuthenticationContext authenticationContext) {
        OAuth2Authorization authorization = authenticationContext.getAuthorization();
        OidcIdToken idToken = authorization.getToken(OidcIdToken.class).getToken();
        OAuth2AccessToken accessToken = authenticationContext.getAccessToken();
        Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(idToken.getClaims(),
                accessToken.getScopes());

        return scopeRequestedClaims;
    }

    private Map<String, Object> getClaimsRequestedByScope(Map<String, Object> claims,
                                                                 Set<String> requestedScopes) {
        Set<String> scopeRequestedClaimNames = new HashSet<>(32);
        scopeRequestedClaimNames.add(StandardClaimNames.SUB);

        if (requestedScopes.contains(OidcScopes.ADDRESS)) {
            scopeRequestedClaimNames.add(StandardClaimNames.ADDRESS);
        }
        if (requestedScopes.contains(OidcScopes.EMAIL)) {
            scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
        }
        if (requestedScopes.contains(OidcScopes.PHONE)) {
            scopeRequestedClaimNames.addAll(PHONE_CLAIMS);
        }
        if (requestedScopes.contains(OidcScopes.PROFILE)) {
            scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
        }

        configProps.getAuthorizedScopes().stream()
                .filter(requestedScopes::contains)
                .forEach(scopeRequestedClaimNames::add);

        Map<String, Object> requestedClaims = new HashMap<>(claims);
        requestedClaims.keySet().removeIf((claimName) -> !scopeRequestedClaimNames.contains(claimName));

        return requestedClaims;
    }
}
