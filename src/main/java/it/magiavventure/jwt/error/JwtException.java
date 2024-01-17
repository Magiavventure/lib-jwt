package it.magiavventure.jwt.error;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.common.model.Error;

public class JwtException extends MagiavventureException {
    public JwtException(Error error) {
        super(error);
    }
}
