package com.example.api_gateway.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public class GatewaySecurityProperties {

	private final Jwt jwt = new Jwt();

	public Jwt getJwt() {
		return jwt;
	}

	public static class Jwt {

		private String secret;
		private List<String> publicPaths = new ArrayList<>();
		private String userIdClaim = "userId";
		private String tenantIdClaim = "tenantId";
		private String rolesClaim = "roles";
		private String createdAtClaim = "iat";
		private String expiryClaim = "exp";

		public String getSecret() {
			return secret;
		}

		public void setSecret(String secret) {
			this.secret = secret;
		}

		public List<String> getPublicPaths() {
			return publicPaths;
		}

		public void setPublicPaths(List<String> publicPaths) {
			this.publicPaths = publicPaths;
		}

		public String getUserIdClaim() {
			return userIdClaim;
		}

		public void setUserIdClaim(String userIdClaim) {
			this.userIdClaim = userIdClaim;
		}

		public String getTenantIdClaim() {
			return tenantIdClaim;
		}

		public void setTenantIdClaim(String tenantIdClaim) {
			this.tenantIdClaim = tenantIdClaim;
		}

		public String getRolesClaim() {
			return rolesClaim;
		}

		public void setRolesClaim(String rolesClaim) {
			this.rolesClaim = rolesClaim;
		}

		public String getRoleClaim() {
			return rolesClaim;
		}

		public void setRoleClaim(String roleClaim) {
			this.rolesClaim = roleClaim;
		}

		public String getCreatedAtClaim() {
			return createdAtClaim;
		}

		public void setCreatedAtClaim(String createdAtClaim) {
			this.createdAtClaim = createdAtClaim;
		}

		public String getExpiryClaim() {
			return expiryClaim;
		}

		public void setExpiryClaim(String expiryClaim) {
			this.expiryClaim = expiryClaim;
		}
	}
}
