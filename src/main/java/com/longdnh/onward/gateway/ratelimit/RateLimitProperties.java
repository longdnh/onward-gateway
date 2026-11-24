package com.longdnh.onward.gateway.ratelimit;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;

/**
 * Per-client limit for the public POST endpoints that create accounts or send email. Expressed as
 * "at most {@code maxRequests} per {@code window}", the same policy Account used to enforce on its own;
 * RateLimitConfiguration translates it into a token bucket.
 */
@Validated
@ConfigurationProperties(prefix = "gateway.rate-limit.public-auth")
public record RateLimitProperties(

        @NotEmpty List<String> paths,

        @Positive int maxRequests,

        @NotNull Duration window) {

    /** Bucket size in tokens; the bucket refills one token per second. */
    public int bucketCapacity() {
        return Math.toIntExact(window.toSeconds());
    }

    /** Cost of one request, so that {@code maxRequests} of them empty a full bucket. */
    public int tokensPerRequest() {
        int tokens = bucketCapacity() / maxRequests;

        if (tokens < 1) {
            throw new IllegalArgumentException(
                    "gateway.rate-limit.public-auth: window must be at least maxRequests seconds");
        }

        return tokens;
    }
}
