package fr.algofi.hnn.springsecuritytuto.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;

@Configuration
@EnableMethodSecurity
public class AppSecurityConfig {

    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return webSecurity -> webSecurity.ignoring().requestMatchers("/h2-console/**");
    }

    @Bean
    SecurityFilterChain customSecurityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeyCloakRoleConverter());
        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) ->
                        requests.requestMatchers(HttpMethod.POST, "/users").access(
                                        new WebExpressionAuthorizationManager("hasAuthority('WRITE_USER') && hasRole('ADMIN')"))
//                                .requestMatchers(HttpMethod.GET, "/users", "/users/{userId}").hasAnyAuthority("READ_USER", "WRITE_USER")
                                .requestMatchers(HttpMethod.GET, "/users", "/users/{userId}").hasRole("USER")
                                .requestMatchers(HttpMethod.POST, "/topics/{topicId}/opinions").hasAuthority("WRITE_OPINION")
                                .requestMatchers(HttpMethod.POST, "/topics").hasAuthority("WRITE_TOPIC")
                                .requestMatchers(HttpMethod.GET, "/topics", "/topics/{topicId}").permitAll()
                                .requestMatchers(HttpMethod.GET, "/error").permitAll());
        http.oauth2ResourceServer(rsc -> rsc.jwt(jwtConfigurer ->
                jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
