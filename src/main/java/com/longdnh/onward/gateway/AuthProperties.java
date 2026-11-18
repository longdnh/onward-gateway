package com.longdnh.onward.gateway;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;

/**
 * What the gateway needs to verify an access token: where Account publishes its keys, and the issuer
 * and audience every token must carry. Values mirror app.auth.* in Account.
 */
@Validated
@ConfigurationProperties(prefix = "gateway.auth")
public record AuthProperties(

        @NotBlank String jwkSetUri,

        @NotBlank String issuer,

        @NotBlank String audience,

        /**
         * Routes reachable without a token: the public auth flows of Account and the key discovery
         * document. Everything else needs a valid access token. Ant-style patterns.
         */
        @NotEmpty List<String> publicPaths) {
}
