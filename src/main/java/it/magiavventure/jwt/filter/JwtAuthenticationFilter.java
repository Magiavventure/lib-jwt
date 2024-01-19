package it.magiavventure.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.error.handler.DefaultExceptionHandler;
import it.magiavventure.common.model.HttpError;
import it.magiavventure.common.model.User;
import it.magiavventure.jwt.config.JwtProperties;
import it.magiavventure.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final JwtProperties jwtProperties;
    private final DefaultExceptionHandler defaultExceptionHandler;

    public JwtAuthenticationFilter(JwtService jwtService, JwtProperties jwtProperties, DefaultExceptionHandler defaultExceptionHandler) {
        this.jwtService = jwtService;
        this.jwtProperties = jwtProperties;
        this.defaultExceptionHandler = defaultExceptionHandler;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            String token = jwtService.resolveAndValidateToken(request);
            User user = jwtService.getUser(token);
            //TODO edit authorities
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,
                    null, List.of(new SimpleGrantedAuthority("user")));
            authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            filterChain.doFilter(request, response);
        } catch(MagiavventureException magiavventureException) {
            handleException(response, magiavventureException);
        }
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        return Optional.ofNullable(jwtProperties.getExcludedEndpoints())
                .orElse(new ArrayList<>())
                .stream()
                .anyMatch(exEndpoint -> AntPathRequestMatcher.antMatcher(
                        HttpMethod.valueOf(exEndpoint.getMethod()), exEndpoint.getPath()).matches(request));
    }

    private void handleException(HttpServletResponse response,
                                 MagiavventureException magiavventureException) throws IOException {
        ResponseEntity<HttpError> responseEntity
                = defaultExceptionHandler.handleException(magiavventureException);
        response.setStatus(responseEntity.getStatusCode().value());
        response.setContentType("application/json");
        ObjectMapper mapper = new ObjectMapper();
        response.getWriter().print(mapper.writeValueAsString(responseEntity.getBody()));
        response.flushBuffer();
    }
}
