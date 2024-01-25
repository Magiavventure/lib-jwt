package it.magiavventure.jwt.service;

import io.jsonwebtoken.Claims;
import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.model.Error;
import it.magiavventure.jwt.config.JwtProperties;
import it.magiavventure.mongo.model.Category;
import it.magiavventure.mongo.model.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
@DisplayName("Jwt service tests")
class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    @Spy
    private JwtProperties jwtProperties = buildJwtProperties();

    @Captor
    private ArgumentCaptor<Claims> claimsArgumentCaptor;

    @Test
    @DisplayName("Build and parse a valid JWT")
    void buildValidJwtAndParse_ok() {
        User user = buildUser();
        String token = jwtService.buildJwt(user);
        Assertions.assertNotNull(token);
        Claims claims = jwtService.parseJwtClaims(token);
        Assertions.assertNotNull(claims);
        Assertions.assertEquals(user.getId().toString(), claims.getSubject());
    }

    @Test
    @DisplayName("Get valid JWT from request to parse for get user")
    void givenValidJwt_parseClaims_ok() {
        User user = buildUser();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", jwtService.buildJwt(user));
        String token = jwtService.resolveAndValidateToken(request);
        Assertions.assertNotNull(token);
        Claims claims = jwtService.parseJwtClaims(token);
        Assertions.assertNotNull(claims);
        Assertions.assertEquals(user.getId().toString(), claims.getSubject());
        User userFromJwt = jwtService.getUser(token);
        Assertions.assertNotNull(userFromJwt);
        Assertions.assertEquals(user.getId(), userFromJwt.getId());
        Assertions.assertEquals(user.getName(), userFromJwt.getName());
        Assertions.assertIterableEquals(user.getPreferredCategories(), userFromJwt.getPreferredCategories());
        Assertions.assertIterableEquals(user.getAuthorities(), userFromJwt.getAuthorities());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "fwefwefwefwefw"})
    @DisplayName("Get empty JWT from request to parse")
    void givenEmptyJwt_throwException_ok(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", token);
        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> jwtService.resolveAndValidateToken(request));

        Assertions.assertNotNull(exception);
        Error error = exception.getError();
        Assertions.assertNotNull(error);
        Assertions.assertEquals("jwt-not-valid", error.getKey());
    }

    @Test
    @DisplayName("Get expired JWT from request to parse")
    void givenExpiredJwt_throwException_ok() {
        User user = buildUser();
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", buildToken(user));
        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> jwtService.resolveAndValidateToken(request));

        Assertions.assertNotNull(exception);
        Error error = exception.getError();
        Assertions.assertNotNull(error);
        Assertions.assertEquals("jwt-expired", error.getKey());
    }

    @Test
    @DisplayName("Get token header")
    void retrieveTokenHeader_fromJwtProperties_ok(){
        String headerName = jwtService.getTokenHeader();

        Assertions.assertEquals("mg-a-token", headerName);
    }

    private User buildUser() {
        return User
                .builder()
                .id(UUID.randomUUID())
                .name("name")
                .preferredCategories(List.of(Category
                        .builder()
                        .id(UUID.randomUUID())
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
        JwtProperties.EndpointProperties endpointProperties = new JwtProperties.EndpointProperties();
        endpointProperties.setPath("/path");
        endpointProperties.setMethod("GET");
        jwtProperties.setExcludedEndpoints(List.of(endpointProperties));
        return jwtProperties;
    }

    private String buildToken(User user) {
        JwtProperties jwtProperties = buildJwtProperties();
        jwtProperties.setValidity(-3L);
        JwtService jwtService = new JwtService(jwtProperties);
        return jwtService.buildJwt(user);
    }
}
