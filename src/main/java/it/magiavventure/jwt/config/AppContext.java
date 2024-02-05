package it.magiavventure.jwt.config;

import it.magiavventure.mongo.entity.EUser;
import lombok.Data;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.annotation.RequestScope;

@Data
@Component
@RequestScope
public class AppContext {
    private EUser user;
    private String jwt;
}
