package com.hayden.authorization.credits;

import com.hayden.authorization.user.CdcUserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/credits")
@RequiredArgsConstructor
public class CreditsController {

    private final CdcUserRepository userRepository;


    @PostMapping("/increment")
    public ResponseEntity<Void> increment(@RequestHeader("Stripe-Signature") String sigHeader,
                                          @RequestBody String payload) {
        return ResponseEntity.ok().build();
    }


}
