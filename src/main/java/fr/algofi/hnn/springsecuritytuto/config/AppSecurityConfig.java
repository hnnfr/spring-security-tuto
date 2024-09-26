package fr.algofi.hnn.springsecuritytuto.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class AppSecurityConfig {

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurity -> webSecurity.ignoring().requestMatchers("/h2-console/**");
    }

    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        // accepting only HTTPS
//        http.requiresChannel(rm -> rm.anyRequest().requiresSecure());
//        http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidsession").maximumSessions(1).maxSessionsPreventsLogin(true));

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) ->
                        requests.requestMatchers(HttpMethod.POST, "/users").access(
                                    new WebExpressionAuthorizationManager("hasAuthority('WRITE_USER') && hasRole('ADMIN')"))
                                .requestMatchers(HttpMethod.GET, "/users", "/users/{userId}").hasAnyAuthority("READ_USER", "WRITE_USER")
                                .requestMatchers(HttpMethod.POST, "/topics/{topicId}/opinions").hasAuthority("WRITE_OPINION")
                                .requestMatchers(HttpMethod.POST, "/topics").hasAuthority("WRITE_TOPIC")
                                .requestMatchers(HttpMethod.GET, "/topics", "/topics/{topicId}").hasAnyAuthority("READ_TOPIC", "WRITE_TOPIC")
                                .requestMatchers(HttpMethod.GET, "/error").permitAll());
        http.formLogin(withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomeBasicAuthenticationEntryPoint()));
        return http.build();
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
