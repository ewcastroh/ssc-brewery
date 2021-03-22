package guru.sfg.brewery.web.controllers;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.util.DigestUtils;

import static org.junit.jupiter.api.Assertions.assertTrue;

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
        System.out.println("No Password Encoded NoOp: ".concat(noOp.encode(PASSWORD)));
    }

    @Test
    void ldapTest() {
        PasswordEncoder ldap = new LdapShaPasswordEncoder();
        String ldapEncoded1 = ldap.encode(PASSWORD);
        String ldapEncoded2 = ldap.encode("guru");
        System.out.println("LDAP Encoded 1:".concat(ldapEncoded1));
        System.out.println("LDAP Encoded 2:".concat(ldapEncoded2));
        assertTrue(ldap.matches(PASSWORD, ldapEncoded1));
    }

    @Test
    void sha256Test() {
        PasswordEncoder sha256 = new StandardPasswordEncoder();
        String sha256Encoded1 = sha256.encode(PASSWORD);
        String sha256Encoded2 = sha256.encode(PASSWORD);
        System.out.println("SHA-256 Encoded 1: ".concat(sha256Encoded1));
        System.out.println("SHA-256 Encoded 2: ".concat(sha256Encoded2));
        assertTrue(sha256.matches(PASSWORD, sha256Encoded2));
    }

    @Test
    void bCryptTest() {
        PasswordEncoder bCrypt = new BCryptPasswordEncoder();
        String bCrypt1 = bCrypt.encode(PASSWORD);
        String bCrypt2 = bCrypt.encode(PASSWORD);
        System.out.println("BCrypt Encoded 1: ".concat(bCrypt1));
        System.out.println("BCrypt Encoded 2: ".concat(bCrypt2));
        assertTrue(bCrypt.matches(PASSWORD, bCrypt1));
        assertTrue(bCrypt.matches(PASSWORD, bCrypt2));
    }
}
