package it.magiavventure.jwt.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.jwt.config.JwtProperties;
import it.magiavventure.jwt.error.JwtException;
import it.magiavventure.mongo.model.User;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.TimeUnit;

@Component
public class JwtService {
    private final JwtParser jwtParser;
    private final JwtProperties jwtProperties;
    private final ObjectMapper objectMapper;

    public JwtService(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.jwtParser = Jwts
                .parser()
                .verifyWith(createSecretKey(jwtProperties.getSecret()))
                .build();
        this.objectMapper = new ObjectMapper()
                .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public String buildJwt(User user) {

        Claims claims = Jwts
                .claims()
                .subject(user.getId().toString())
                .add(objectMapper.convertValue(user, new TypeReference<Map<String, Object>>() {}))
                .build();

        return Jwts
                .builder()
                .claims(claims)
                .expiration(getExpiration())
                .signWith(createSecretKey(jwtProperties.getSecret()))
                .compact();
    }

    public Claims parseJwtClaims(String jwt) {
        try {
            return jwtParser.parseSignedClaims(jwt).getPayload();
        } catch (ExpiredJwtException exception) {
            throw MagiavventureException.of(JwtException.JWT_EXPIRED);
        } catch (io.jsonwebtoken.JwtException | IllegalArgumentException exception) {
            throw MagiavventureException.of(JwtException.JWT_NOT_VALID);
        }
    }

    public String resolveAndValidateToken(HttpServletRequest request) {
        String token = resolveToken(request);
        parseJwtClaims(token);
        return token;
    }
    
    public User getUser(String jwt) {
        Claims claims = parseJwtClaims(jwt);
        return Optional.ofNullable(claims)
                .map(c -> objectMapper.convertValue(c, User.class))
                .orElse(null);
    }

    private String resolveToken(HttpServletRequest request) {
        return Optional.ofNullable(request.getHeader(jwtProperties.getHeader()))
                .filter(token -> !token.isEmpty() && !token.isBlank())
                .orElseThrow(() -> MagiavventureException.of(JwtException.JWT_NOT_VALID));
    }

    private Date getExpiration() {
        return new Date(new Date().getTime()
                + TimeUnit.of(ChronoUnit.MINUTES).toMillis(jwtProperties.getValidity()));
    }
    
    private SecretKey createSecretKey(String secret) {
        return Keys.hmacShaKeyFor(getByteArraySecret(secret));
    }

    private byte[] getByteArraySecret(String secret) {
        return secret.getBytes(StandardCharsets.UTF_8);
    }

}
