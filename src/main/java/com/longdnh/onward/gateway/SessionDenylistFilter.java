package com.longdnh.onward.gateway;

import java.time.Instant;
import java.util.List;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * The second layer of authentication (docs section 7): a token can be valid and still belong to a session
 * that Account has revoked. Runs after the JWT was verified and reads the entries Account writes (7.2):
 * <ul>
 * <li>{@code denied:session:<sid>} present: the session was revoked.</li>
 * <li>{@code denied:user:<sub>} present and the token's {@code iat} is not after its value: every session
 * of the user was revoked at that instant; tokens issued later belong to a new session and pass.</li>
 * </ul>
 * One round trip per authenticated request (MGET of both keys). Fail-open by decision: on a Redis error
 * or timeout the request continues on the strength of the token alone, and the failure is logged.
 * Deliberately not a bean: WebFlux registers every WebFilter bean in the global chain as well, which
 * would run this check twice per request. SecurityConfiguration constructs it and places it in the
 * security chain only.
 */
@Slf4j
public class SessionDenylistFilter implements WebFilter {

    static final String SESSION_KEY_PREFIX = "denied:session:";
    static final String USER_KEY_PREFIX = "denied:user:";

    private final ReactiveStringRedisTemplate redis;
    private final AuthProperties properties;

    public SessionDenylistFilter(ReactiveStringRedisTemplate redis, AuthProperties properties) {
        this.redis = redis;
        this.properties = properties;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(context -> context.getAuthentication())
                // Public paths reach here anonymous (or not at all); only a verified token is checked.
                .filter(JwtAuthenticationToken.class::isInstance)
                .cast(JwtAuthenticationToken.class)
                .flatMap(authentication -> isDenied(authentication.getToken()))
                .defaultIfEmpty(false)
                .flatMap(denied -> denied
                        ? ApiErrors.unauthenticated(exchange.getResponse())
                        : chain.filter(exchange));
    }

    private Mono<Boolean> isDenied(Jwt jwt) {
        String sessionId = jwt.getClaimAsString("sid");
        String userId = jwt.getSubject();
        Instant issuedAt = jwt.getIssuedAt();

        if (sessionId == null || userId == null || issuedAt == null) {
            // Account always sets these; a token without them is not one the denylist can reason about.
            return Mono.just(true);
        }

        return redis.opsForValue()
                .multiGet(List.of(SESSION_KEY_PREFIX + sessionId, USER_KEY_PREFIX + userId))
                .timeout(properties.denylistTimeout())
                .map(values -> values.get(0) != null || revokedAfterIssue(values.get(1), issuedAt))
                .onErrorResume(exception -> {
                    log.warn("Denylist unavailable, letting the request through on the token alone: {}",
                            exception.getClass().getName());

                    return Mono.just(false);
                });
    }

    private static boolean revokedAfterIssue(String revokedAtEpochSeconds, Instant issuedAt) {
        if (revokedAtEpochSeconds == null) {
            return false;
        }

        try {
            return issuedAt.getEpochSecond() <= Long.parseLong(revokedAtEpochSeconds);
        } catch (NumberFormatException exception) {
            log.warn("Denylist user entry has a non-numeric value; treating the token as revoked");

            return true;
        }
    }
}
