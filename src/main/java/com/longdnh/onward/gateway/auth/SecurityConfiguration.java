package com.longdnh.onward.gateway.auth;

import com.longdnh.onward.gateway.error.ApiErrors;
import com.longdnh.onward.gateway.ratelimit.PublicAuthRateLimitFilter;
import com.longdnh.onward.gateway.ratelimit.RateLimitProperties;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
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


@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

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
            ServerHttpSecurity http, AuthProperties properties, ReactiveJwtDecoder jwtDecoder,
            ReactiveStringRedisTemplate redis, RedisRateLimiter publicAuthRateLimiter,
            RateLimitProperties rateLimitProperties) {
        String[] publicPaths = properties.publicPaths().toArray(String[]::new);
        var sessionDenylistFilter = new SessionDenylistFilter(redis, properties);
        var rateLimitFilter = new PublicAuthRateLimitFilter(publicAuthRateLimiter, rateLimitProperties);

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
                        .authenticationEntryPoint((exchange, exception) ->
                                ApiErrors.unauthenticated(exchange.getResponse()))
                        .accessDeniedHandler((exchange, exception) ->
                                ApiErrors.forbidden(exchange.getResponse())))
                .exceptionHandling(errors -> errors
                        .authenticationEntryPoint((exchange, exception) ->
                                ApiErrors.unauthenticated(exchange.getResponse()))
                        .accessDeniedHandler((exchange, exception) ->
                                ApiErrors.forbidden(exchange.getResponse())))
                // Before AUTHENTICATION: the limited paths are public, so the count happens before any
                // token work, and a flooded client costs nothing beyond one Redis call.
                .addFilterBefore(rateLimitFilter, SecurityWebFiltersOrder.AUTHENTICATION)
                // After AUTHORIZATION: anonymous requests to protected paths were already rejected, and the
                // verified token is in the reactive security context for the filter to read.
                .addFilterAfter(sessionDenylistFilter, SecurityWebFiltersOrder.AUTHORIZATION)
                .build();
    }
}
