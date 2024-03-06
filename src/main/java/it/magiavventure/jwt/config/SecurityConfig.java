package it.magiavventure.jwt.config;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.error.handler.DefaultExceptionHandler;
import it.magiavventure.jwt.error.JwtException;
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
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
                                                   DefaultExceptionHandler defaultExceptionHandler,
                                                   AppContext appContext) throws Exception {
        httpSecurity
                .csrf(AbstractHttpConfigurer::disable)
                .cors(httpSecurityCorsConfigurer ->
                        httpSecurityCorsConfigurer.configurationSource(corsConfigurationSource(jwtProperties)))
                .sessionManagement(httpSecuritySessionManagementConfigurer -> httpSecuritySessionManagementConfigurer
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        addRequestMatchers(httpSecurity, jwtProperties);

        httpSecurity.addFilterBefore(jwtAuthenticationFilter(jwtProperties, jwtService,
                        defaultExceptionHandler, appContext),
                UsernamePasswordAuthenticationFilter.class);

        httpSecurity
                .exceptionHandling(httpSecurityExceptionHandlingConfigurer ->
                        httpSecurityExceptionHandlingConfigurer
                                .accessDeniedHandler((request, response, accessDeniedException) -> {
                                    throw MagiavventureException.of(JwtException.ACCESS_DENIED);
                                }
                        ));

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
                            requestMatcher.hasAnyAuthority(endpoint.getRoles());
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
    CorsConfigurationSource corsConfigurationSource(JwtProperties jwtProperties) {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(jwtProperties.getCors().getAllowedOrigins());
        configuration.setAllowedMethods(jwtProperties.getCors().getAllowedMethods());
        configuration.setAllowedHeaders(jwtProperties.getCors().getAllowedHeaders());
        configuration.setExposedHeaders(jwtProperties.getCors().getExposedHeaders());
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtProperties jwtProperties, JwtService jwtService,
                                                           DefaultExceptionHandler defaultExceptionHandler,
                                                           AppContext appContext) {
        return new JwtAuthenticationFilter(jwtService, jwtProperties, defaultExceptionHandler, appContext);
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

}
