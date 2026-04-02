package com.example.api_gateway.security;

import java.time.Instant;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.server.ServerWebExchange;

import com.example.api_gateway.config.GatewaySecurityProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import io.jsonwebtoken.JwtException;
import reactor.core.publisher.Mono;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthenticationGlobalFilter implements GlobalFilter, Ordered {

	private final GatewaySecurityProperties gatewaySecurityProperties;
	private final JwtTokenService jwtTokenService;
	private final ObjectMapper objectMapper;
	private final AntPathMatcher pathMatcher = new AntPathMatcher();

	public JwtAuthenticationGlobalFilter(GatewaySecurityProperties gatewaySecurityProperties,
			JwtTokenService jwtTokenService, ObjectMapper objectMapper) {
		this.gatewaySecurityProperties = gatewaySecurityProperties;
		this.jwtTokenService = jwtTokenService;
		this.objectMapper = objectMapper;
	}

	@Override
	public int getOrder() {
		return Ordered.HIGHEST_PRECEDENCE;
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		// Let browser preflight requests pass through.
		// "If the request is an OPTIONS request(pre-check request sent by the browser before the actual API call) → just allow it and skip security"
		if (HttpMethod.OPTIONS.equals(exchange.getRequest().getMethod())) {
			return chain.filter(exchange);
		}

		String path = exchange.getRequest().getPath().pathWithinApplication().value();
		// Skip token check for public URLs like login and health checks.
		if (isPublicPath(path)) {
			return chain.filter(exchange);
		}

		// Read the token from the request header.
		String authorizationHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
		if (!hasBearerToken(authorizationHeader)) {
			return unauthorized(exchange, "Missing Bearer token");
		}

		String token = authorizationHeader.substring(7).trim();
		try {
			// Read values from the token and pass them to the next service.
			GatewayUserContext userContext = jwtTokenService.parse(token);
			ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
				.headers(headers -> {
					headers.set("X-User-Subject", userContext.subject());
					headers.set("X-User-Id", userContext.userId());
					headers.set("X-Tenant-Id", userContext.tenantId());
					headers.set("X-User-Roles", String.join(",", userContext.roles()));
					headers.set("X-User-Role", userContext.roles().get(0));
					headers.set("X-Token-Created-At", userContext.createdAt().toString());
					headers.set("X-Token-Expiry", userContext.expiry().toString());
				})
					.build();

			return chain.filter(exchange.mutate().request(mutatedRequest).build());
		}
		catch (JwtException | IllegalArgumentException ex) {
			// Stop here if the token is broken or expired.
			return unauthorized(exchange, "Invalid or expired token");
		}
	}

	private boolean isPublicPath(String path) {
		// Check whether this URL is allowed without a token.
		for (String publicPath : gatewaySecurityProperties.getJwt().getPublicPaths()) {
			if (pathMatcher.match(publicPath, path)) {
				return true;
			}
		}
		return false;
	}

	private boolean hasBearerToken(String authorizationHeader) {
		return authorizationHeader != null && authorizationHeader.startsWith("Bearer ")
				&& authorizationHeader.length() > 7;
	}

	private Mono<Void> unauthorized(ServerWebExchange exchange, String message) {
		// Send a simple 401 response back to the client.
		exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
		exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);

		ObjectNode body = objectMapper.createObjectNode();
		body.put("timestamp", Instant.now().toString());
		body.put("status", HttpStatus.UNAUTHORIZED.value());
		body.put("error", "Unauthorized");
		body.put("message", message);
		body.put("path", exchange.getRequest().getPath().value());

		byte[] responseBytes;
		try {
			responseBytes = objectMapper.writeValueAsBytes(body);
		}
		catch (Exception ex) {
			responseBytes = ("{\"error\":\"Unauthorized\",\"message\":\"" + message + "\"}").getBytes();
		}

		return exchange.getResponse().writeWith(Mono.just(exchange.getResponse().bufferFactory().wrap(responseBytes)));
	}
}
