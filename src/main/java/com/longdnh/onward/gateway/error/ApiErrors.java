package com.longdnh.onward.gateway.error;

import java.nio.charset.StandardCharsets;

import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;

import reactor.core.publisher.Mono;

/** Writes the same JSON shape as Account's ApiError, so clients see one error contract whoever rejects them. */
public final class ApiErrors {

    private static final String UNAUTHENTICATED_BODY = """
            {"code":"UNAUTHENTICATED","message":"Authentication is required"}""";

    private static final String FORBIDDEN_BODY = """
            {"code":"FORBIDDEN","message":"Access is denied"}""";

    private static final String RATE_LIMITED_BODY = """
            {"code":"RATE_LIMITED","message":"Too many requests. Try again later"}""";

    private ApiErrors() {
    }

    public static Mono<Void> unauthenticated(ServerHttpResponse response) {
        response.getHeaders().set(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        return write(response, HttpStatus.UNAUTHORIZED, UNAUTHENTICATED_BODY);
    }

    public static Mono<Void> forbidden(ServerHttpResponse response) {
        return write(response, HttpStatus.FORBIDDEN, FORBIDDEN_BODY);
    }

    public static Mono<Void> rateLimited(ServerHttpResponse response, long retryAfterSeconds) {
        response.getHeaders().set(HttpHeaders.RETRY_AFTER, Long.toString(retryAfterSeconds));

        return write(response, HttpStatus.TOO_MANY_REQUESTS, RATE_LIMITED_BODY);
    }

    private static Mono<Void> write(ServerHttpResponse response, HttpStatus status, String body) {
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().setCacheControl("no-store");

        DataBuffer buffer = response.bufferFactory().wrap(body.getBytes(StandardCharsets.UTF_8));

        return response.writeWith(Mono.just(buffer));
    }
}
