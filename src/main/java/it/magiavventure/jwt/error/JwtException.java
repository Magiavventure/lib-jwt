package it.magiavventure.jwt.error;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.model.Error;

public class JwtException extends MagiavventureException {
    public static final String JWT_EXPIRED = "jwt-expired";
    public static final String JWT_NOT_VALID = "jwt-not-valid";
    public JwtException(Error error) {
        super(error);
    }
}
