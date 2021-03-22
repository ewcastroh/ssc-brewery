package guru.sfg.brewery.config;

import guru.sfg.brewery.security.CustomPasswordEncoderFactories;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.ExampleMatcher;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.LdapShaPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.password.StandardPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests(authorize -> {
                    authorize
                            .antMatchers("/", "/webjars/**", "/login", "/resources/**").permitAll()
                            .antMatchers("/beers/find", "/beers*").permitAll()
                            .antMatchers(HttpMethod.GET, "/api/v1/beer/**").permitAll()
                            .mvcMatchers(HttpMethod.GET, "/api/v1/beerUpc/{upc}").permitAll();
                })
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().and()
                .httpBasic();
    }

    /*@Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("spring")
                .password("guru")
                .roles("ADMIN")
                .build();

        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(admin, user);
    }*/

    // In this way we use Fluent API. Here we have to use {noop} no password encoding.
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("spring")
                //.password("{noop}guru")
                // Using NoOpPasswordEncoder Bean we don't need to use {noop} in password
                //.password("{SSHA}Cnaz+iY1ysAzuUSSn8aLyiBQwNrcmR7VE1zqKw==")
                // Password using BCrypt. We use {bcrypt} to indicate which password encoder we'll use.
                .password("{bcrypt}$2a$10$Bcu6TPxcxTBA.vf5ZczILO7tfAhaX4sJ3B0M6cKqusboqhWV03Wxy")
                .roles("ADMIN")
                .and()
                .withUser("user")
                //.password("password")
                // Using NoOpPasswordEncoder Bean we don't need to use {noop} in password
                //.password("password")
                // Password encode using LDAP
                //.password("{SSHA}nRTMXs6l1VdyL19ZCPh4PgMl0O03dMp9LuWYUA==")
                // Password using SHA-256. We use {sha256} to indicate which password encoder we'll use.
                .password("{sha256}244f0c01da4c89e35b89927f8920c634fa9f92d2edf6b49168c5b1eb1f240f44bc5a56f1290f42e7")
                // Password using BCrypt
                //.password("$2a$10$ebiFTDBHSrTWylESpbVFzOYtRJAC1hgnPQDCFs7XUAZWQiVZnjPp6")
                .roles("USER");

        auth.inMemoryAuthentication()
                .withUser("scott")
                //.password("{noop}tiger")
                // Using NoOpPasswordEncoder Bean we don't need to use {noop} in password
                //.password("tiger")
                // Password encode using LDAP. We use {ldap} to indicate which password encoder we'll use.
                //.password("{ldap}{SSHA}aXLGJm4Ki/iUq4wx1m5htNjWlLc+ArEryso+vQ==")
                // Password using BCrypt with strength of 15
                .password("{bcrypt15}$2a$15$zsy5wQIdEvzZiTbiA34EMOndfvOGfuqhE.hPyQpJzngZpkWCZiX9m")
                .roles("CUSTOMER");
    }

    // Using NoOpPasswordEncoder Bean we don't need to use {noop} in password.
    // Always generates a different hashed string using a SALT value.
    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }*/

    // Password encode using LDAP
    // Always generates a different hashed string using a SALT value.
    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return new LdapShaPasswordEncoder();
    }*/

    // Password using SHA-256
    // Always generates a different hashed string using a SALT value.
    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return new StandardPasswordEncoder();
    }*/

    // Password using BCrypt. This is the Spring recommendation.
    // Always generates a different hashed string using a SALT value.
    // It can setting up a strong in the constructor
    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }*/

    // Using PasswordEncoderFactories.createDelegatingPasswordEncoder() we can use different password encoders
    /*@Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }*/

    // Using CustomPasswordEncoderFactories.createDelegatingPasswordEncoder() we can use different custom password encoders
    @Bean
    public PasswordEncoder passwordEncoder() {
        return CustomPasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
