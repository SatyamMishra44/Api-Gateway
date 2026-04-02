package com.example.api_gateway.security;

import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.example.api_gateway.config.GatewaySecurityProperties;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtTokenService {

	private final GatewaySecurityProperties gatewaySecurityProperties;
	private final Key signingKey;

	public JwtTokenService(GatewaySecurityProperties gatewaySecurityProperties) {
		this.gatewaySecurityProperties = gatewaySecurityProperties;
		String secret = gatewaySecurityProperties.getJwt().getSecret();

		// The gateway must know the same secret that auth-service uses to sign the token.
		if (!StringUtils.hasText(secret)) {
			throw new IllegalStateException("app.security.jwt.secret must be configured");
		}
		// Keep the secret long enough so it is hard to guess.
		if (secret.getBytes(StandardCharsets.UTF_8).length < 32) {
			throw new IllegalStateException("JWT secret must be at least 32 bytes long");
		}
		SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
		this.signingKey = secretKey;
	}

	public GatewayUserContext parse(String token) {
		// Read and verify the token before trusting any of its values.
		Claims claims = Jwts.parserBuilder()
			.setSigningKey(signingKey)
			.build()
			.parseClaimsJws(token)
			.getBody();

		// Pull the values that auth-service puts into the token.
		String subject = resolveRequiredStringClaim(claims, "sub", claims.getSubject());
		String userId = resolveRequiredStringClaim(claims, gatewaySecurityProperties.getJwt().getUserIdClaim(), null);
		String tenantId = resolveRequiredStringClaim(claims, gatewaySecurityProperties.getJwt().getTenantIdClaim(), null);
		List<String> roles = resolveRequiredStringListClaim(claims, gatewaySecurityProperties.getJwt().getRolesClaim());
		Instant createdAt = resolveRequiredInstantClaim(claims, gatewaySecurityProperties.getJwt().getCreatedAtClaim(),
				claims.getIssuedAt());
		Instant expiry = resolveRequiredInstantClaim(claims, gatewaySecurityProperties.getJwt().getExpiryClaim(),
				claims.getExpiration());

		// Do not allow tokens that are already expired.
		if (expiry.isBefore(Instant.now())) {
			throw new IllegalArgumentException("JWT has expired");
		}

		return new GatewayUserContext(subject, userId, tenantId, roles, createdAt, expiry);
	}

	private String resolveRequiredStringClaim(Claims claims, String claimName, String fallback) {
		String value = resolveStringClaim(claims, claimName);
		if (StringUtils.hasText(value)) {
			return value;
		}
		if (StringUtils.hasText(fallback)) {
			return fallback;
		}
		throw new IllegalArgumentException("Missing required JWT claim: " + claimName);
	}

	private String resolveStringClaim(Claims claims, String claimName) {
		Object value = claims.get(claimName);
		if (value == null) {
			return null;
		}
		return value.toString();
	}

	private List<String> resolveRequiredStringListClaim(Claims claims, String claimName) {
		Object value = claims.get(claimName);
		List<String> roles = toStringList(value);
		if (!roles.isEmpty()) {
			return roles;
		}
		throw new IllegalArgumentException("Missing required JWT claim: " + claimName);
	}

	private Instant resolveRequiredInstantClaim(Claims claims, String claimName, Date fallback) {
		Instant value = resolveInstantClaim(claims.get(claimName));
		if (value != null) {
			return value;
		}
		if (fallback != null) {
			return fallback.toInstant();
		}
		throw new IllegalArgumentException("Missing required JWT claim: " + claimName);
	}

	private Instant resolveInstantClaim(Object value) {
		if (value == null) {
			return null;
		}
		if (value instanceof Instant instant) {
			return instant;
		}
		if (value instanceof Date date) {
			return date.toInstant();
		}
		if (value instanceof Number number) {
			long numericValue = number.longValue();
			// JWT timestamps are usually stored in seconds. Keep millis support too.
			if (Math.abs(numericValue) < 10_000_000_000L) {
				return Instant.ofEpochSecond(numericValue);
			}
			return Instant.ofEpochMilli(numericValue);
		}
		String text = value.toString();
		if (!StringUtils.hasText(text)) {
			return null;
		}
		return Instant.parse(text);
	}

	private List<String> toStringList(Object value) {
		if (value == null) {
			return List.of();
		}
		List<String> values = new ArrayList<>();
		if (value instanceof Collection<?> collection) {
			for (Object item : collection) {
				addTextValue(values, item);
			}
			return List.copyOf(values);
		}
		if (value.getClass().isArray()) {
			int length = Array.getLength(value);
			for (int i = 0; i < length; i++) {
				addTextValue(values, Array.get(value, i));
			}
			return List.copyOf(values);
		}
		String text = value.toString();
		if (!StringUtils.hasText(text)) {
			return List.of();
		}
		if (text.contains(",")) {
			for (String part : text.split(",")) {
				addTextValue(values, part);
			}
			return List.copyOf(values);
		}
		values.add(text);
		return List.copyOf(values);
	}

	private void addTextValue(List<String> values, Object item) {
		if (item == null) {
			return;
		}
		String text = item.toString().trim();
		if (StringUtils.hasText(text)) {
			values.add(text);
		}
	}
}
