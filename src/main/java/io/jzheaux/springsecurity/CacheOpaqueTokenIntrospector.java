package io.jzheaux.springsecurity;

import java.net.URL;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
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
		Collection<GrantedAuthority> authorities = new ArrayList();
		Map<String, Object> claims = response.toJSONObject();
		Iterator var5;
		if (response.getAudience() != null) {
			List<String> audiences = new ArrayList();
			var5 = response.getAudience().iterator();

			while(var5.hasNext()) {
				Audience audience = (Audience)var5.next();
				audiences.add(audience.getValue());
			}

			claims.put("aud", Collections.unmodifiableList(audiences));
		}

		if (response.getClientID() != null) {
			claims.put("client_id", response.getClientID().getValue());
		}

		Instant iat;
		if (response.getExpirationTime() != null) {
			iat = response.getExpirationTime().toInstant();
			claims.put("exp", iat);
		}

		if (response.getIssueTime() != null) {
			iat = response.getIssueTime().toInstant();
			claims.put("iat", iat);
		}

		if (response.getIssuer() != null) {
			claims.put("iss", this.issuer(response.getIssuer().getValue()));
		}

		if (response.getNotBeforeTime() != null) {
			claims.put("nbf", response.getNotBeforeTime().toInstant());
		}

		if (response.getScope() != null) {
			List<String> scopes = Collections.unmodifiableList(response.getScope().toStringList());
			claims.put("scope", scopes);
			var5 = scopes.iterator();

			while(var5.hasNext()) {
				String scope = (String)var5.next();
				StringBuilder var10003 = new StringBuilder();
				this.getClass();
				authorities.add(new SimpleGrantedAuthority(var10003.append("SCOPE_").append(scope).toString()));
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