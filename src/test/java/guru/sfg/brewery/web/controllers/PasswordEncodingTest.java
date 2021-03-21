package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.util.DigestUtils;

public class PasswordEncodingTest {
    
    static final String PASSWORD = "password";

    @Test
    void hashingExample() {
        System.out.println("Hashed Password:" + DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        String saltedPassword = PASSWORD.concat("ThisIsMySALTVALUE");
        System.out.println("Salted Hash Password:" + DigestUtils.md5DigestAsHex(saltedPassword.getBytes()));
    }

    @Test
    void noOperationPasswordEncoderNoopTest() {
        PasswordEncoder noOp = NoOpPasswordEncoder.getInstance();
        System.out.println("No Passwrd Encoded NoOp: ".concat(noOp.encode(PASSWORD)));
    }
}
