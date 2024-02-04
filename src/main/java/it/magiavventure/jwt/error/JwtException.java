package it.magiavventure.jwt.error;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.model.Error;

public class JwtException extends MagiavventureException {
    public static final String JWT_EXPIRED = "jwt-expired";
    public static final String JWT_NOT_VALID = "jwt-not-valid";
    public static final String JWT_ACCESS_DENIED = "jwt-access-denied";
    public static final String USER_BLOCKED = "user-blocked";
    public static final String USER_NOT_FOUND = "user-not-found";

    public JwtException(Error error) {
        super(error);
    }

}
