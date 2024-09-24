package fr.algofi.hnn.springsecuritytuto.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class AppSecurityConfig {
    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
//        http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());
        http.authorizeHttpRequests((requests) ->
                requests.requestMatchers("/users", "/users/{userId}").authenticated()
                        .requestMatchers("/topics", "/topics/{topicId}", "/error").permitAll());
        http.formLogin(withDefaults());
//        http.formLogin(AbstractHttpConfigurer::disable);
        http.httpBasic(withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails userA = User.withUsername("userA").password("{noop}12345").roles("USER").build();
        UserDetails userB = User.withUsername("userB").password("{bcrypt}$2a$12$iGmU8r5w1vtEfyw/6N1jteVtXa454n.HvFbhCG94vphJ6mkRA0NFW").roles("USER").build();
        UserDetails admin = User.withUsername("superuser").password("{bcrypt}$2a$12$DX9uKAZgWIsFM/kj7romVO2EZVuPRzRnjXXJz3UAwYEpb.GAi5IJ2").roles("ADMIN").build();

        return new InMemoryUserDetailsManager(userA, userB, admin);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
