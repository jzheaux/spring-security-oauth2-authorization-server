package io.jzheaux.springsecurity;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.stream.Collectors;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.client.ClientInformation;
import com.nimbusds.oauth2.sdk.client.ClientMetadata;
import com.nimbusds.oauth2.sdk.id.ClientID;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class ClientDetailsService implements UserDetailsService {

	ClientInformation client;

	public ClientDetailsService() {
		ClientMetadata metadata = new ClientMetadata();
		metadata.setScope(new Scope("message:read", "message:write", "profile"));
		metadata.setGrantTypes(new HashSet<>(Arrays.asList(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN, GrantType.PASSWORD, GrantType.CLIENT_CREDENTIALS)));
		metadata.setName("The Client");
		metadata.setRedirectionURI(URI.create("http://localhost:8080/login/oauth2/code/sso"));
		this.client = new ClientInformation(
				new ClientID("client"),
				new Date(0),
				metadata,
				new Secret("{noop}secret"));
	}

	@Override
	public UserDetails loadUserByUsername(String clientId) throws UsernameNotFoundException {
		if (clientId.equals(this.client.getID().getValue())) {
			return new ClientInformationUserDetails(this.client);
		}
		throw new UsernameNotFoundException("couldn't find client");
	}

	private static class ClientInformationUserDetails extends ClientInformation
			implements UserDetails, CredentialsContainer {

		String password;
		Collection<GrantedAuthority> authorities;

		public ClientInformationUserDetails(ClientInformation client) {
			super(client.getID(), client.getIDIssueDate(), client.getMetadata(), null);
			this.password = client.getSecret().getValue();

			Collection<GrantedAuthority> authorities = new ArrayList<>();
			authorities.add(new SimpleGrantedAuthority("ROLE_CLIENT"));
			authorities.addAll(client.getMetadata().getGrantTypes().stream()
					.map(grantType -> new SimpleGrantedAuthority("ROLE_" + grantType))
					.collect(Collectors.toList()));
			this.authorities = Collections.unmodifiableCollection(authorities);
		}

		@Override
		public Collection<? extends GrantedAuthority> getAuthorities() {
			return this.authorities;
		}

		@Override
		public String getPassword() {
			return this.password;
		}

		@Override
		public String getUsername() {
			return super.getID().getValue();
		}

		@Override
		public boolean isAccountNonExpired() {
			return true;
		}

		@Override
		public boolean isAccountNonLocked() {
			return true;
		}

		@Override
		public boolean isCredentialsNonExpired() {
			return true;
		}

		@Override
		public boolean isEnabled() {
			return true;
		}

		@Override
		public void eraseCredentials() {
			this.password = null;
		}
	}
}
