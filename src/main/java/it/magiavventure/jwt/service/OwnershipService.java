package it.magiavventure.jwt.service;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.jwt.config.AppContext;
import it.magiavventure.jwt.error.JwtException;
import it.magiavventure.mongo.entity.EUser;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class OwnershipService {

    private final AppContext appContext;
    public static final String USER_AUTHORITY = "user";
    public static final String ADMIN_AUTHORITY = "admin";

    public void validateOwnership(Object value) {
        EUser eUser = retrieveCurrentUser();
        if(eUser.getAuthorities().contains(ADMIN_AUTHORITY)) return;
        if(value instanceof UUID && !value.equals(eUser.getId()))
            throw MagiavventureException.of(JwtException.OWNERSHIP);
        if(value instanceof String && !value.equals(eUser.getName()))
            throw MagiavventureException.of(JwtException.OWNERSHIP);
    }

    private EUser retrieveCurrentUser() {
        return Optional.ofNullable(appContext)
                .map(AppContext::getUser)
                .orElseThrow(() -> MagiavventureException.of(JwtException.NO_OWNERSHIP_CHECK));
    }
}
