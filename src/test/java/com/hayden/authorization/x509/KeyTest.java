package com.hayden.authorization.x509;

import com.hayden.utilitymodule.security.KeyConfigProperties;
import com.hayden.utilitymodule.security.KeyFiles;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@ActiveProfiles("test-auth")
public class KeyTest {

    @Autowired
    KeyFiles keyFiles;
    @Autowired
    KeyConfigProperties keyConfigProperties;

    @Test
    public void doTestKeyFiles() {
        var created = Assertions.assertDoesNotThrow(() -> keyFiles.getKeyPair());
        assertThat(created).isNotNull();
        assertThat(keyConfigProperties.getKeyPath().toFile()).exists();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pem").toFile()).exists();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pub.pem").toFile()).exists();

        keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pem").toFile().delete();
        keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pub.pem").toFile().delete();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pem").toFile()).doesNotExist();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + "pub.pem").toFile()).doesNotExist();

        created = Assertions.assertDoesNotThrow(() -> keyFiles.getKeyPair());
        assertThat(created).isNotNull();
        assertThat(keyConfigProperties.getKeyPath().toFile()).exists();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pem").toFile()).exists();

        created = Assertions.assertDoesNotThrow(() -> keyFiles.getKeyPair());
        assertThat(created).isNotNull();
        assertThat(keyConfigProperties.getKeyPath().toFile()).exists();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pem").toFile()).exists();
        assertThat(keyConfigProperties.getKeyPath().resolve(keyConfigProperties.getKeyName() + ".pub.pem").toFile()).exists();
    }

}
