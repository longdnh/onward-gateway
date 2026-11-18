package com.longdnh.onward.gateway;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

import reactor.core.publisher.Mono;

@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

    /** Same JSON shape as Account's ApiError, so clients see one error contract whoever rejects them. */
    private static final String UNAUTHENTICATED_BODY = """
            {"code":"UNAUTHENTICATED","message":"Authentication is required"}""";

    private static final String FORBIDDEN_BODY = """
            {"code":"FORBIDDEN","message":"Access is denied"}""";

    @Bean
    public Clock clock() {
        return Clock.systemUTC();
    }

    /**
     * Keys come from Account's JWKS endpoint and are cached; a token whose kid is unknown triggers one
     * refetch, which is how a rotated key is picked up. The validators repeat Account's own rules
     * (issuer, audience, no missing expiry, no clock skew) so the gateway is never more lenient than
     * the service behind it.
     */
    @Bean
    public ReactiveJwtDecoder jwtDecoder(AuthProperties properties, Clock clock) {
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder
                .withJwkSetUri(properties.jwkSetUri())
                .jwsAlgorithm(SignatureAlgorithm.RS256)
                .build();

        JwtTimestampValidator timestamps = new JwtTimestampValidator(Duration.ZERO);

        timestamps.setClock(clock);
        timestamps.setAllowEmptyExpiryClaim(false);

        OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
                "aud",
                values -> values != null && values.contains(properties.audience()));

        decoder.setJwtValidator(
                new DelegatingOAuth2TokenValidator<>(
                        timestamps,
                        new JwtIssuerValidator(properties.issuer()),
                        audience));

        return decoder;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http, AuthProperties properties, ReactiveJwtDecoder jwtDecoder) {
        String[] publicPaths = properties.publicPaths().toArray(String[]::new);

        return http
                // CSRF is enforced by Account on its cookie-backed endpoints; the gateway only forwards.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers(publicPaths).permitAll()
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder))
                        .authenticationEntryPoint((exchange, exception) -> {
                            exchange.getResponse().getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

                            return write(exchange.getResponse(), HttpStatus.UNAUTHORIZED, UNAUTHENTICATED_BODY);
                        })
                        .accessDeniedHandler((exchange, exception) ->
                                write(exchange.getResponse(), HttpStatus.FORBIDDEN, FORBIDDEN_BODY)))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((exchange, exception) ->
                                write(exchange.getResponse(), HttpStatus.UNAUTHORIZED, UNAUTHENTICATED_BODY))
                        .accessDeniedHandler((exchange, exception) ->
                                write(exchange.getResponse(), HttpStatus.FORBIDDEN, FORBIDDEN_BODY)))
                .build();
    }

    private static Mono<Void> write(ServerHttpResponse response, HttpStatus status, String body) {
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().setCacheControl("no-store");

        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }
}
