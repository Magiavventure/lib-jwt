package it.magiavventure.jwt.config;

import it.magiavventure.common.error.handler.DefaultExceptionHandler;
import it.magiavventure.jwt.config.JwtProperties;
import it.magiavventure.jwt.filter.JwtAuthenticationFilter;
import it.magiavventure.jwt.service.JwtService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.Objects;
import java.util.Optional;

@Slf4j
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity,
                                                   JwtProperties jwtProperties, JwtService jwtService,
                                                   DefaultExceptionHandler defaultExceptionHandler) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        addRequestMatchers(httpSecurity, jwtProperties);

        httpSecurity.addFilterBefore(jwtAuthenticationFilter(jwtProperties, jwtService, defaultExceptionHandler),
                UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }

    private void addRequestMatchers(HttpSecurity httpSecurity,
                                    JwtProperties jwtProperties) throws Exception {
        httpSecurity.authorizeHttpRequests(requests -> {
            Optional.ofNullable(jwtProperties.getEndpoints())
                    .orElse(new ArrayList<>())
                    .forEach(endpoint -> {
                        log.info("Adding requestMatcher for path '{}' - authenticated: {} - roles: {}",
                                endpoint.getPath(), endpoint.getAuthenticated(), endpoint.getRoles());
                        var requestMatcher = requests.requestMatchers(endpoint.getPath());
                        if (Objects.nonNull(endpoint.getRoles()) && endpoint.getRoles().length > 0) {
                            requestMatcher.hasAnyRole(endpoint.getRoles());
                        }
                        if (Boolean.TRUE.equals(endpoint.getAuthenticated())) {
                            requestMatcher.authenticated();
                        } else {
                            requestMatcher.permitAll();
                        }
                    });
            requests.anyRequest().authenticated();
        });
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtProperties jwtProperties, JwtService jwtService,
                                                           DefaultExceptionHandler defaultExceptionHandler) {
        return new JwtAuthenticationFilter(jwtService, jwtProperties, defaultExceptionHandler);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
