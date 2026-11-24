package com.longdnh.onward.gateway.ratelimit;

import com.longdnh.onward.gateway.error.ApiErrors;

import java.net.InetSocketAddress;
import java.util.Set;

import org.springframework.cloud.gateway.filter.ratelimit.RateLimiter;
import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.http.HttpMethod;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

/**
 * Moved here from Account (docs section 7.4): behind the gateway every request reaches Account from the
 * gateway's address, so a per-IP limit can only be enforced where the client address is still visible.
 * Each limited path has its own bucket per client, so exhausting one does not block the others. Keyed on
 * the connection address; a caller-supplied X-Forwarded-For is never trusted. If the gateway itself is
 * ever placed behind a load balancer, that is the one place to add a trusted-proxy configuration.
 */
@Slf4j
public class PublicAuthRateLimitFilter implements WebFilter {

    private static final String LIMITER_ID = "public-auth";

    private final RedisRateLimiter limiter;
    private final Set<String> limitedPaths;
    private final int tokensPerRequest;

    public PublicAuthRateLimitFilter(RedisRateLimiter limiter, RateLimitProperties properties) {
        this.limiter = limiter;
        this.limitedPaths = Set.copyOf(properties.paths());
        this.tokensPerRequest = properties.tokensPerRequest();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        var request = exchange.getRequest();
        String path = request.getPath().value();

        if (request.getMethod() != HttpMethod.POST || !limitedPaths.contains(path)) {
            return chain.filter(exchange);
        }

        String key = path + "|" + clientAddress(exchange);

        return limiter.isAllowed(LIMITER_ID, key)
                .doOnNext(response -> log.debug("Rate limit key={} allowed={} remaining={}",
                        key, response.isAllowed(), response.getHeaders().get(limiter.getRemainingHeader())))
                .flatMap(response -> response.isAllowed()
                        ? chain.filter(exchange)
                        : ApiErrors.rateLimited(exchange.getResponse(), retryAfterSeconds(response)));
    }

    private static String clientAddress(ServerWebExchange exchange) {
        InetSocketAddress address = exchange.getRequest().getRemoteAddress();

        return address == null ? "unknown" : address.getAddress().getHostAddress();
    }

    /** Tokens refill one per second, so the wait is the shortfall for one request's worth of tokens. */
    private long retryAfterSeconds(RateLimiter.Response response) {
        long remaining = 0;

        try {
            remaining = Long.parseLong(response.getHeaders().getOrDefault(limiter.getRemainingHeader(), "0"));
        } catch (NumberFormatException ignored) {
            // Treat as an empty bucket.
        }

        return Math.max(1, tokensPerRequest - remaining);
    }
}
