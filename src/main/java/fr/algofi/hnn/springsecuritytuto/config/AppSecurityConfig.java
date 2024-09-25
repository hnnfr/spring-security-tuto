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
//        http.authorizeHttpRequests((requests) -> requests.anyRequest().permitAll());

        // accepting only HTTPS
//        http.requiresChannel(rm -> rm.anyRequest().requiresSecure());

//        http.sessionManagement(smc -> smc.invalidSessionUrl("/invalidsession").maximumSessions(1).maxSessionsPreventsLogin(true));

        http.csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((requests) ->
                requests.requestMatchers("/users", "/users/{userId}").authenticated()
                        .requestMatchers(HttpMethod.POST, "/topics").authenticated()
                        .requestMatchers(HttpMethod.POST, "/topics/{topicId}/opinions").authenticated()
                        .requestMatchers(HttpMethod.GET, "/topics", "/topics/{topicId}", "/error").permitAll());
        http.formLogin(withDefaults());
//        http.formLogin(AbstractHttpConfigurer::disable);
//        http.httpBasic(withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomeBasicAuthenticationEntryPoint()));
        return http.build();
    }

//    @Bean
//    UserDetailsService userDetailsService() {
//        UserDetails userA = User.withUsername("userA").password("{noop}hong123nam!").roles("USER").build();
//        UserDetails userB = User.withUsername("userB").password("{bcrypt}$2a$12$iGmU8r5w1vtEfyw/6N1jteVtXa454n.HvFbhCG94vphJ6mkRA0NFW").roles("USER").build();
//        UserDetails admin = User.withUsername("superuser").password("{bcrypt}$2a$12$DX9uKAZgWIsFM/kj7romVO2EZVuPRzRnjXXJz3UAwYEpb.GAi5IJ2").roles("ADMIN").build();
//
//        return new InMemoryUserDetailsManager(userA, userB, admin);
//    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();
    }
}
