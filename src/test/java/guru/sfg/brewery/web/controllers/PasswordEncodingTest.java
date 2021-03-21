package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.util.DigestUtils;

public class PasswordEncodingTest {
    
    static final String PASSWORD = "password";

    @Test
    void hashingExample() {
        System.out.println("Hashed Password:" + DigestUtils.md5DigestAsHex(PASSWORD.getBytes()));
        String saltedPassword = PASSWORD.concat("ThisIsMySALTVALUE");
        System.out.println("Salted Hash Password:" + DigestUtils.md5DigestAsHex(saltedPassword.getBytes()));
    }
}
