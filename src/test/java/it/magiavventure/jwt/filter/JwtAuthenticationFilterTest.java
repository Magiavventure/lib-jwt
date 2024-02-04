package it.magiavventure.jwt.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import it.magiavventure.common.configuration.CommonProperties;
import it.magiavventure.common.configuration.CommonProperties.ErrorsProperties;
import it.magiavventure.common.configuration.CommonProperties.ErrorsProperties.ErrorMessage;
import it.magiavventure.common.error.handler.DefaultExceptionHandler;
import it.magiavventure.common.mapper.HttpErrorMapper;
import it.magiavventure.common.model.HttpError;
import it.magiavventure.jwt.config.JwtProperties;
import it.magiavventure.jwt.config.JwtProperties.EndpointProperties;
import it.magiavventure.jwt.service.JwtService;
import it.magiavventure.jwt.service.UserJwtService;
import it.magiavventure.mongo.entity.EUser;
import it.magiavventure.mongo.model.Category;
import it.magiavventure.mongo.model.User;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.mockito.*;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;


@DisplayName("Jwt authentication filter tests")
class JwtAuthenticationFilterTest {

    private JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserJwtService userJwtService = Mockito.mock(UserJwtService.class);

    @BeforeEach
    void beforeEach() {
        JwtProperties jwtProperties = buildJwtProperties();
        JwtService jwtService = new JwtService(jwtProperties, userJwtService);
        DefaultExceptionHandler defaultExceptionHandler = new DefaultExceptionHandler(buildCommonProperties(),
                Mappers.getMapper(HttpErrorMapper.class));
        this.jwtAuthenticationFilter = new JwtAuthenticationFilter(jwtService, jwtProperties, defaultExceptionHandler);
    }

    @Test
    @DisplayName("Given a valid jwt filter not throw exception")
    void givenValidJwt_chainDoFilter_ok() throws ServletException, IOException {
        UUID id = UUID.randomUUID();
        User user = buildUser(id);
        EUser eUser = buildEUser(id);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", buildToken(user, false));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        Mockito.when(userJwtService.retrieveById(user.getId()))
                .thenReturn(eUser);

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        Mockito.verify(userJwtService).retrieveById(user.getId());

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        Assertions.assertNotNull(authentication);
        EUser userLoggedIn = (EUser) authentication.getPrincipal();
        Assertions.assertNotNull(userLoggedIn);
        Assertions.assertEquals(user.getId(), userLoggedIn.getId());
        Assertions.assertEquals(user.getName(), userLoggedIn.getName());
        Assertions.assertIterableEquals(user.getPreferredCategories(), userLoggedIn.getPreferredCategories());
        Assertions.assertIterableEquals(user.getAuthorities(), userLoggedIn.getAuthorities());
        Assertions.assertEquals(1, authentication.getAuthorities().size());
        authentication.getAuthorities().stream().findFirst()
                .ifPresent(authority -> Assertions.assertEquals("user", authority.getAuthority()));
    }

    @Test
    @DisplayName("Given an expired jwt filter throw exception with code jwt-expired")
    void givenExpiredJwt_throwExpiredException_ok() throws ServletException, IOException {
        User user = buildUser(UUID.randomUUID());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", buildToken(user, true));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        Assertions.assertEquals(401, response.getStatus());
        ObjectMapper objectMapper = new ObjectMapper();
        HttpError error = objectMapper.readValue(response.getContentAsByteArray(), HttpError.class);
        Assertions.assertNotNull(error);
        Assertions.assertEquals("jwt-expired", error.getCode());
        Assertions.assertEquals("jwt scaduto", error.getMessage());
        Assertions.assertEquals("jwt scaduto", error.getDescription());
        Assertions.assertEquals(401, error.getStatus());
    }

    @Test
    @DisplayName("Given a null jwt filter throw exception with code jwt-not-valid")
    void givenNullJwt_throwNotValidException_ok() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", "");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();

        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        Assertions.assertEquals(401, response.getStatus());
        ObjectMapper objectMapper = new ObjectMapper();
        HttpError error = objectMapper.readValue(response.getContentAsByteArray(), HttpError.class);
        Assertions.assertNotNull(error);
        Assertions.assertEquals("jwt-not-valid", error.getCode());
        Assertions.assertEquals("jwt non valido", error.getMessage());
        Assertions.assertEquals("jwt non valido", error.getDescription());
        Assertions.assertEquals(401, error.getStatus());
    }

    @Test
    @DisplayName("Path should not filter return true")
    void givenRequest_pathShouldNotFilter_returnTrue() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setServletPath("/path");

        boolean shouldNotFilter = jwtAuthenticationFilter.shouldNotFilter(request);

        Assertions.assertTrue(shouldNotFilter);
    }

    @Test
    @DisplayName("Path should not filter return false")
    void givenRequest_pathShouldNotFilter_returnFalse() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setMethod("GET");
        request.setServletPath("/pathnew");

        boolean shouldNotFilter = jwtAuthenticationFilter.shouldNotFilter(request);

        Assertions.assertFalse(shouldNotFilter);
    }

    private String buildToken(User user, boolean expired) {
        JwtProperties jwtProperties = buildJwtProperties();
        if(expired)
            jwtProperties.setValidity(0L);
        JwtService jwtService = new JwtService(jwtProperties, Mockito.mock(UserJwtService.class));
        return jwtService.buildJwt(user);
    }

    private User buildUser(UUID id) {
        return User
                .builder()
                .id(id)
                .name("name")
                .preferredCategories(List.of(Category
                        .builder()
                        .id(UUID.fromString("b2609f3d-e31a-4247-886b-ee52dde3dab6"))
                        .name("name")
                        .background("background")
                        .build()))
                .authorities(List.of("user"))
                .build();
    }

    private EUser buildEUser(UUID id) {
        return EUser
                .builder()
                .id(id)
                .name("name")
                .preferredCategories(List.of(Category
                        .builder()
                        .id(UUID.fromString("b2609f3d-e31a-4247-886b-ee52dde3dab6"))
                        .name("name")
                        .background("background")
                        .build()))
                .authorities(List.of("user"))
                .build();
    }

    private JwtProperties buildJwtProperties() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setSecret("cXVlc3RhIMOoIGxhIGZha2Ugc2VjcmV0IHBlciBnZW5lcmFyZSBpIHRva2" +
                "VuIG5laSB0ZXN0IGRpIG1hZ2lhdnZlbnR1cmUsIGZhdGUgY29tZSB2b2xldGU=");
        jwtProperties.setHeader("mg-a-token");
        jwtProperties.setValidity(30L);
        EndpointProperties endpointProperties = new EndpointProperties();
        endpointProperties.setPath("/path");
        endpointProperties.setMethod("GET");
        jwtProperties.setExcludedEndpoints(List.of(endpointProperties));
        return jwtProperties;
    }

    private CommonProperties buildCommonProperties() {
        CommonProperties commonProperties = new CommonProperties();
        ErrorsProperties errorsProperties = new ErrorsProperties();
        Map<String, ErrorMessage> jwtErrors = new HashMap<>();
        jwtErrors.put("jwt-not-valid", ErrorMessage
                .builder()
                        .code("jwt-not-valid")
                        .description("jwt non valido")
                        .message("jwt non valido")
                        .status(401)
                .build());
        jwtErrors.put("jwt-expired", ErrorMessage
                .builder()
                .code("jwt-expired")
                .description("jwt scaduto")
                .message("jwt scaduto")
                .status(401)
                .build());
        errorsProperties.setJwtErrorsMessages(jwtErrors);
        commonProperties.setErrors(errorsProperties);
        return commonProperties;
    }
}
