package io.jzheaux.springsecurity;

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.id.Audience;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.Cache;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionException;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.stereotype.Component;

import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.AUDIENCE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.CLIENT_ID;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.EXPIRES_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUED_AT;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.ISSUER;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.NOT_BEFORE;
import static org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionClaimNames.SCOPE;

@Component
public class CacheOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

	@Autowired
	Cache accessTokenCache;

	@Override
	public OAuth2AuthenticatedPrincipal introspect(String s) {
		TokenIntrospectionSuccessResponse details =
				this.accessTokenCache.get(s, TokenIntrospectionSuccessResponse.class);
		if (details == null) {
			throw new OAuth2IntrospectionException("Could not find active access token");
		}
		return convertClaimsSet(details);
	}

	private OAuth2AuthenticatedPrincipal convertClaimsSet(TokenIntrospectionSuccessResponse response) {
		Collection<GrantedAuthority> authorities = new ArrayList<>();
		Map<String, Object> claims = response.toJSONObject();
		if (response.getAudience() != null) {
			List<String> audiences = new ArrayList<>();
			for (Audience audience : response.getAudience()) {
				audiences.add(audience.getValue());
			}
			claims.put(AUDIENCE, Collections.unmodifiableList(audiences));
		}
		if (response.getClientID() != null) {
			claims.put(CLIENT_ID, response.getClientID().getValue());
		}
		if (response.getExpirationTime() != null) {
			Instant exp = response.getExpirationTime().toInstant();
			claims.put(EXPIRES_AT, exp);
		}
		if (response.getIssueTime() != null) {
			Instant iat = response.getIssueTime().toInstant();
			claims.put(ISSUED_AT, iat);
		}
		if (response.getIssuer() != null) {
			claims.put(ISSUER, issuer(response.getIssuer().getValue()));
		}
		if (response.getNotBeforeTime() != null) {
			claims.put(NOT_BEFORE, response.getNotBeforeTime().toInstant());
		}
		if (response.getScope() != null) {
			List<String> scopes = Collections.unmodifiableList(response.getScope().toStringList());
			claims.put(SCOPE, scopes);

			for (String scope : scopes) {
				authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
			}
		}

		return new DefaultOAuth2AuthenticatedPrincipal(claims, authorities);
	}


	private URL issuer(String uri) {
		try {
			return new URL(uri);
		} catch (Exception var3) {
			throw new OAuth2IntrospectionException("Invalid iss value: " + uri);
		}
	}

}