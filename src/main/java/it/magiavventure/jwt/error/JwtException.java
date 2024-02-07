package it.magiavventure.jwt.error;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.model.Error;

public class JwtException extends MagiavventureException {
    public static final String NOT_AUTHENTICATED = "not-authenticated";
    public static final String ACCESS_DENIED = "access-denied";
    public static final String OWNERSHIP = "ownership";

    public JwtException(Error error) {
        super(error);
    }

}
