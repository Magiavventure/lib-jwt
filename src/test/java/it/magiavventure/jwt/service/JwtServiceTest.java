package it.magiavventure.jwt.service;

import io.jsonwebtoken.Claims;
import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.model.Error;
import it.magiavventure.jwt.config.JwtProperties;
import it.magiavventure.mongo.entity.EUser;
import it.magiavventure.mongo.model.Category;
import it.magiavventure.mongo.model.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
@DisplayName("Jwt service tests")
class JwtServiceTest {
    @InjectMocks
    private JwtService jwtService;

    @Mock
    private UserJwtService userJwtService;

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

        Mockito.when(userJwtService.retrieveById(user.getId()))
                .thenReturn(EUser.builder().build());

        String token = jwtService.resolveToken(request);
        Assertions.assertNotNull(token);
        Claims claims = jwtService.parseJwtClaims(token);
        Assertions.assertNotNull(claims);
        Assertions.assertEquals(user.getId().toString(), claims.getSubject());

        EUser eUser = jwtService.extractUser(token);

        Mockito.verify(userJwtService).retrieveById(user.getId());

        Assertions.assertNotNull(eUser);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " "})
    @DisplayName("Get empty/blank JWT from request to parse")
    void givenEmptyJwt_throwException_ok(String token) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("mg-a-token", token);
        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> jwtService.resolveToken(request));

        Assertions.assertNotNull(exception);
        Error error = exception.getError();
        Assertions.assertNotNull(error);
        Assertions.assertEquals("jwt-not-valid", error.getKey());
    }

    @Test
    @DisplayName("Parse wrong JWT throw exception")
    void givenWrongJwt_parse_throwException() {
        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> jwtService.parseJwtClaims("fowefweofbwefw"));

        Assertions.assertNotNull(exception);
        Error error = exception.getError();
        Assertions.assertNotNull(error);
        Assertions.assertEquals("jwt-not-valid", error.getKey());
    }

    @Test
    @DisplayName("Parse expired JWT throw exception")
    void givenExpiredJwt_throwException_ok() {
        User user = buildUser();
        String expiredToken = buildToken(user);
        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> jwtService.parseJwtClaims(expiredToken));

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
        JwtService jwtService = new JwtService(jwtProperties, userJwtService);
        return jwtService.buildJwt(user);
    }
}
