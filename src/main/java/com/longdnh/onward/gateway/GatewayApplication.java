package com.longdnh.onward.gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * The single entry point for clients. Routes requests to the services and verifies the access token
 * once, so the services behind it only re-check the signature. See docs/microservice-decomposition.md
 * section 7 in onward-be.
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class GatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewayApplication.class, args);
    }
}
