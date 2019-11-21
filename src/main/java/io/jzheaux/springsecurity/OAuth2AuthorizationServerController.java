package io.jzheaux.springsecurity;

import java.net.URI;
import java.security.Principal;
import java.util.Arrays;
import java.util.Date;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.AuthorizationErrorResponse;
import com.nimbusds.oauth2.sdk.AuthorizationRequest;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.id.Subject;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import com.nimbusds.openid.connect.sdk.SubjectType;
import com.nimbusds.openid.connect.sdk.UserInfoSuccessResponse;
import com.nimbusds.openid.connect.sdk.claims.UserInfo;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import com.sun.org.apache.xpath.internal.operations.Mod;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.web.context.request.RequestAttributes.SCOPE_REQUEST;

@Controller
public class OAuth2AuthorizationServerController {
	@Autowired
	private Cache authorizationCodeCache;

	@Autowired
	private Cache accessTokenCache;

	@Autowired
	private Cache refreshTokenCache;

	@Autowired
	private UserDetailsService clientDetailsService;

	@Autowired
	private UserDetailsService userDetailsService;

	@Autowired
	AuthenticationManager endUserAuthenticationManager;

	@Value("${issuerUri}")
	String issuer;

	@GetMapping("/.well-known/openid-configuration")
	public HTTPResponse openidConfiguration() {
		OIDCProviderMetadata metadata = new OIDCProviderMetadata(
				new Issuer(issuer),
				Arrays.asList(SubjectType.PUBLIC),
				URI.create(issuer + "/jwks"));
		metadata.setAuthorizationEndpointURI(URI.create(this.issuer + "/authorize"));
		metadata.setTokenEndpointURI(URI.create(this.issuer + "/token"));
		metadata.setUserInfoEndpointURI(URI.create(this.issuer + "/userinfo"));
		metadata.setResponseTypes(Arrays.asList(ResponseType.getDefault()));
		metadata.setIDTokenJWSAlgs(Arrays.asList(JWSAlgorithm.RS256));
		metadata.setScopes(new Scope("profile", "message:read", "message:write"));
		HTTPResponse response = new HTTPResponse(200);
		response.setContent(metadata.toJSONObject().toString());
		return response;
	}

	@GetMapping("/userinfo")
	public HTTPResponse userinfo(@AuthenticationPrincipal Principal user) {
		UserInfo info = new UserInfo(new Subject(user.getName()));
		info.setName(user.getName());
		return new UserInfoSuccessResponse(info).toHTTPResponse();
	}

	@PostMapping(path="/introspect")
	public HTTPResponse introspect(HTTPRequest req) throws Exception {
		TokenIntrospectionRequest request = TokenIntrospectionRequest.parse(req);
		TokenIntrospectionResponse response =
				this.accessTokenCache.get(request.getToken().getValue(), TokenIntrospectionResponse.class);
		if (response == null) {
			response = new TokenIntrospectionSuccessResponse.Builder(false).build();
		}
		return response.toHTTPResponse();
	}

	@GetMapping(path="/authorize", params="response_type=code")
	public ModelAndView authorize
			(HTTPRequest req, @AuthenticationPrincipal Principal user) throws Exception {
		AuthorizationRequest request = AuthorizationRequest.parse(req);
		ClientInformation client = (ClientInformation)
				this.clientDetailsService.loadUserByUsername(request.getClientID().getValue());
		if (client == null) {
			String error = new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT,
					request.getState(), request.getResponseMode()).toHTTPResponse().getContent();
			throw new IllegalArgumentException(error);
		}

		if (!client.getMetadata().getRedirectionURI().equals(request.getRedirectionURI())) {
			String error = new AuthorizationErrorResponse(request.getRedirectionURI(), OAuth2Error.INVALID_GRANT,
					request.getState(), request.getResponseMode()).toHTTPResponse().getContent();
			throw new IllegalArgumentException(error);
		}

		TokenIntrospectionSuccessResponse details =
				tokenDetails(client, new Subject(user.getName()), request.getScope());
		Tokens tokens = accessAndRefreshTokens(details);
		AuthorizationCode code = new AuthorizationCode();
		this.authorizationCodeCache.put(code.getValue(), tokens);

		String redirect = UriComponentsBuilder.fromUri(client.getMetadata().getRedirectionURI())
				.queryParam("code", code)
				.queryParam("state", request.getState().getValue())
				.build().toUriString();

		return new ModelAndView("redirect:" + redirect);
	}

	@PostMapping(path="/token", params="grant_type=authorization_code")
	public HTTPResponse authorizationCode
			(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		TokenRequest request = TokenRequest.parse(req);

		AuthorizationCodeGrant grant = (AuthorizationCodeGrant) request.getAuthorizationGrant();
		if (!client.getMetadata().getRedirectionURI().equals(grant.getRedirectionURI())) {
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}

		Tokens tokens = this.authorizationCodeCache.get(grant.getAuthorizationCode().getValue(), Tokens.class);
		if (tokens == null) {
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}

		return new AccessTokenResponse(tokens).toHTTPResponse();
	}

	@PostMapping(path="/token", params="grant_type=client_credentials")
	public HTTPResponse clientCredentials
			(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		TokenRequest request = TokenRequest.parse(req);
		TokenIntrospectionSuccessResponse details =
				tokenDetails(client, new Subject(client.getID().getValue()), request.getScope());
		BearerAccessToken bearer = accessToken(details);
		Tokens tokens = new Tokens(bearer, null);
		return new AccessTokenResponse(tokens).toHTTPResponse();
	}

	@PostMapping(path="/token", params="grant_type=password")
	public HTTPResponse passwordGrant
			(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		TokenRequest request = TokenRequest.parse(req);
		ResourceOwnerPasswordCredentialsGrant grant =
				(ResourceOwnerPasswordCredentialsGrant) request.getAuthorizationGrant();
		UsernamePasswordAuthenticationToken token =
				new UsernamePasswordAuthenticationToken(grant.getUsername(), grant.getPassword().getValue());
		Authentication authentication = this.endUserAuthenticationManager.authenticate(token);

		if (authentication.isAuthenticated()) {
			TokenIntrospectionSuccessResponse details =
					tokenDetails(client, new Subject(authentication.getName()), request.getScope());
			BearerAccessToken bearer = accessToken(details);
			Tokens tokens = new Tokens(bearer, null);
			return new AccessTokenResponse(tokens).toHTTPResponse();
		} else {
			throw new AccessDeniedException("access is denied");
		}
	}

	@PostMapping(path="/token", params="grant_type=refresh_token")
	public HTTPResponse refreshToken
			(HTTPRequest req, @AuthenticationPrincipal ClientInformation client) throws Exception {
		TokenRequest request = TokenRequest.parse(req);
		RefreshTokenGrant grant = (RefreshTokenGrant) request.getAuthorizationGrant();
		RefreshToken refreshToken = grant.getRefreshToken();
		TokenIntrospectionResponse response = this.refreshTokenCache.get(refreshToken.getValue(), TokenIntrospectionResponse.class);

		if (response == null) {
			return new TokenErrorResponse(OAuth2Error.INVALID_GRANT).toHTTPResponse();
		}

		TokenIntrospectionSuccessResponse token = response.toSuccessResponse();
		if (!token.getClientID().equals(client.getID())) {
			return new TokenErrorResponse(OAuth2Error.INVALID_CLIENT).toHTTPResponse();
		}

		Tokens tokens = accessAndRefreshTokens(token);
		return new AccessTokenResponse(tokens).toHTTPResponse();
	}

	private BearerAccessToken accessToken(TokenIntrospectionSuccessResponse details) {
		BearerAccessToken bearer = new BearerAccessToken(3600L, details.getScope());
		this.accessTokenCache.put(bearer.getValue(), details);
		return bearer;
	}

	private Tokens accessAndRefreshTokens(TokenIntrospectionSuccessResponse details) {
		BearerAccessToken bearer = accessToken(details);
		RefreshToken refreshToken = new RefreshToken();
		this.refreshTokenCache.put(refreshToken.getValue(), details);
		return new Tokens(bearer, refreshToken);
	}

	private TokenIntrospectionSuccessResponse tokenDetails(ClientInformation client, Subject subject, Scope requestedScope) {
		Scope scope = new Scope(client.getMetadata().getScope());
		scope.retainAll(requestedScope);
		BearerAccessToken bearer = new BearerAccessToken(3600L, scope);
		Date now = new Date();
		return new TokenIntrospectionSuccessResponse.Builder(true)
				.scope(scope)
				.clientID(client.getID())
				.expirationTime(new Date(now.getTime() + bearer.getLifetime()*1000))
				.issueTime(now)
				.issuer(new Issuer(this.issuer))
				.subject(subject)
				.build();
	}
}
