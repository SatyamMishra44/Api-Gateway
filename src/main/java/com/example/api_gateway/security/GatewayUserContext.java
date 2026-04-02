package com.example.api_gateway.security;

import java.time.Instant;
import java.util.List;

public record GatewayUserContext(String subject, String userId, String tenantId, List<String> roles, Instant createdAt,
		Instant expiry) {
}
