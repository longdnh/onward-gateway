package com.longdnh.onward.gateway.ratelimit;

import org.springframework.cloud.gateway.filter.ratelimit.RedisRateLimiter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
public class RateLimitConfiguration {

    /**
     * Spring Cloud Gateway's token bucket in Redis (one Lua script per check, atomic, shared by every
     * gateway instance). A bucket refills one token per second up to {@code window} seconds' worth, and a
     * request costs {@code window / maxRequests} tokens: a fresh client gets {@code maxRequests} at once,
     * then one more every {@code window / maxRequests} seconds, which averages to the configured policy.
     * On a Redis error the limiter allows the request (fail-open, like the denylist).
     */
    @Bean
    public RedisRateLimiter publicAuthRateLimiter(RateLimitProperties properties) {
        return new RedisRateLimiter(1, properties.bucketCapacity(), properties.tokensPerRequest());
    }
}
