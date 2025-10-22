package com.hayden.authorization.oauth2;

import com.hayden.authorization.user.CdcUserRepository;
import lombok.Builder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/v1/tokens")
@RequiredArgsConstructor
@Slf4j
public class TokenController {

    @Builder
    public record TokenResult(List<OAuth2Authorization.Token<OAuth2AccessToken>> token, boolean success, String error) {}

    @Builder
    public record TokenRevocationRequest() {}

    private final OAuth2TokenService tokenService;

    private final CdcUserRepository userRepository;

    @GetMapping("/get-tokens")
    public ResponseEntity<TokenResult> getTokens(@AuthenticationPrincipal Jwt authenticatedPrincipal) {
        return userRepository.findForToken(authenticatedPrincipal)
                .map(c -> {
                    var tokens = tokenService.findByPrincipal(c.getPrincipalName(), c.getPrincipalId().clientId(), 10, 0)
                            .stream().flatMap(oauth -> Optional.ofNullable(oauth.getAccessToken()).stream())
                            .toList();

                    return TokenResult.builder()
                            .token(tokens)
                            .success(true)
                            .build();
                })
                .or(() -> Optional.of(TokenResult.builder().success(false)
                        .error("Could not find user for %s".formatted(authenticatedPrincipal.getSubject())).build()))
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/revoke-token")
    public ResponseEntity<Void> revokeToken(@AuthenticationPrincipal Jwt authenticatedPrincipal,
                                            @RequestBody TokenRevocationRequest tokenToRevoke) {
        return ResponseEntity.internalServerError().body(null);
    }
}
