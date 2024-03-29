package it.magiavventure.jwt.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

@Data
@ConfigurationProperties(prefix = "magiavventure.lib.jwt")
public class JwtProperties {
    private String secret;
    private Long validity;
    private String header;
    private List<EndpointProperties> endpoints;
    private List<EndpointProperties> excludedEndpoints;
    private CorsProperties cors;

    @Data
    public static class CorsProperties {
        private List<String> allowedOrigins;
        private List<String> allowedMethods;
        private List<String> allowedHeaders;
        private List<String> exposedHeaders;
    }

    @Data
    public static class EndpointProperties {
        private String method;
        private String path;
        private String[] roles;
        private Boolean authenticated;
    }
}
