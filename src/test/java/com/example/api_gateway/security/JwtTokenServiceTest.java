package com.example.api_gateway.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.example.api_gateway.config.GatewaySecurityProperties;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

class JwtTokenServiceTest {

	private static final String SECRET = "jwt-dev-secret-jwt-dev-secret-jwt-dev-secret";

	private JwtTokenService jwtTokenService;

	@BeforeEach
	void setUp() {
		GatewaySecurityProperties properties = new GatewaySecurityProperties();
		properties.getJwt().setSecret(SECRET);
		jwtTokenService = new JwtTokenService(properties);
	}

	@Test
	void parsesValidTokenAndExtractsClaims() {
		Instant createdAt = Instant.now().minusSeconds(60).truncatedTo(ChronoUnit.SECONDS);
		Instant expiry = Instant.now().plusSeconds(3600).truncatedTo(ChronoUnit.SECONDS);
		String token = Jwts.builder()
			.setSubject("testuser123@example.com")
			.setIssuedAt(Date.from(createdAt))
			.setExpiration(Date.from(expiry))
			.claim("userId", "user-123")
			.claim("tenantId", "tenant-9")
			.claim("roles", List.of("ROLE_USER"))
			.signWith(Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8)), SignatureAlgorithm.HS256)
			.compact();

		GatewayUserContext context = jwtTokenService.parse(token);

		assertThat(context.subject()).isEqualTo("testuser123@example.com");
		assertThat(context.userId()).isEqualTo("user-123");
		assertThat(context.tenantId()).isEqualTo("tenant-9");
		assertThat(context.roles()).containsExactly("ROLE_USER");
		assertThat(context.createdAt()).isEqualTo(createdAt);
		assertThat(context.expiry()).isEqualTo(expiry);
	}

	@Test
	void rejectsInvalidToken() {
		assertThatThrownBy(() -> jwtTokenService.parse("invalid.token.value"))
			.isInstanceOf(RuntimeException.class);
	}
}
