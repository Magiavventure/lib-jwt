package it.magiavventure.jwt.service;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.jwt.config.AppContext;
import it.magiavventure.jwt.error.JwtException;
import it.magiavventure.mongo.entity.EUser;
import it.magiavventure.mongo.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserJwtService {
    private final UserRepository userRepository;

    @Cacheable(value = "user_entity", key = "#p0")
    public EUser retrieveById(UUID id) {
        return userRepository
                .findById(id)
                .orElseThrow(() -> MagiavventureException.of(JwtException.USER_NOT_FOUND, id.toString()));
    }

    public void validateUser(EUser eUser) {
        LocalDateTime banExpiration = eUser.getBanExpiration();
        if(Objects.nonNull(banExpiration) && banExpiration.isAfter(LocalDateTime.now())) {
            throw MagiavventureException.of(JwtException.USER_BLOCKED);
        }
    }

    public void validateOwnership(EUser eUser, Object value) {
        if(value instanceof UUID && !value.equals(eUser.getId()))
            throw MagiavventureException.of(JwtException.JWT_ACCESS_DENIED);
        if(value instanceof String && !value.equals(eUser.getName()))
            throw MagiavventureException.of(JwtException.JWT_ACCESS_DENIED);
    }

}
