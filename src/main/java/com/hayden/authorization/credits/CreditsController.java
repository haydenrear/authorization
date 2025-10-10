package com.hayden.authorization.credits;

import com.hayden.authorization.user.CdcUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/credits")
@RequiredArgsConstructor
public class CreditsController {

    private final CdcUserRepository userRepository;


    @PostMapping("/stripe/add-credits")
    public ResponseEntity<Void> increment(@RequestHeader("Stripe-Signature") String sigHeader,
                                          @RequestBody String payload) {
        return ResponseEntity.ok().build();
    }

    public record GetCreditsResult(String whatever) {}

    @GetMapping(value = "/get-credits", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<GetCreditsResult> increment(@AuthenticationPrincipal Jwt authenticatedPrincipal) {
        return ResponseEntity.ok().body(new GetCreditsResult("hello"));
    }

}
