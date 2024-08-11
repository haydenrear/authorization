package com.hayden.authorization.web_authn;

import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

@UtilityClass
public class OAuth2WebAuthnGrantType {


    public static final AuthorizationGrantType WEB_AUTHN = new AuthorizationGrantType("WEB_AUTHN");

}
