package com.hayden.authorization.x509;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.security.KeyPair;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@ActiveProfiles("test-auth")
public class KeyTest {

    @Autowired
    KeyFiles keyFiles;

    @Test
    public void doTestKeyFiles() {
        var created = Assertions.assertDoesNotThrow(() -> keyFiles.getKeyPair());
    }

}
