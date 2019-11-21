package io.jzheaux.springsecurity.config;

import java.util.Collections;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@Order(101)
class ClientEndpoints extends WebSecurityConfigurerAdapter {
	@Autowired
	UserDetailsService clientDetailsService;

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.requestMatchers(r -> r.mvcMatchers("/token", "/introspect", "/.well-known/openid-configuration"))
				.authorizeRequests(a -> {
					a.requestMatchers(new GrantTypeMatcher()).access("hasRole(#type)");
					a.mvcMatchers(POST, "/introspect").hasRole("CLIENT");
					a.mvcMatchers(GET, "/.well-known/openid-configuration").permitAll();
					a.anyRequest().denyAll();
				})
				.httpBasic(withDefaults())
				.userDetailsService(this.clientDetailsService)
				.csrf().disable();
	}

	private static class GrantTypeMatcher implements RequestMatcher {
		private AntPathRequestMatcher matcher = new AntPathRequestMatcher("/token", "POST");

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.matcher.matches(request);
		}

		@Override
		public RequestMatcher.MatchResult matcher(HttpServletRequest request) {
			Map<String, String> variables = Collections.singletonMap
					("type", request.getParameter("grant_type"));
			return MatchResult.match(variables);
		}
	}
}

@Configuration
@Order(102)
class UserEndpoints extends WebSecurityConfigurerAdapter {

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests(a -> {
					a.mvcMatchers(GET, "/userinfo").hasAuthority("SCOPE_profile");
					a.anyRequest().authenticated();
				})
				.formLogin(withDefaults())
				.oauth2ResourceServer(OAuth2ResourceServerConfigurer::opaqueToken);
	}

	@Bean
	AuthenticationManager endUserAuthenticationManager(UserDetailsService userDetailsService) throws Exception {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setUserDetailsService(userDetailsService);
		return provider::authenticate;
	}

	@Bean
	@Override
	public UserDetailsService userDetailsService() {
		return new InMemoryUserDetailsManager(
				User.withDefaultPasswordEncoder()
						.username("user")
						.password("password")
						.roles("USER")
						.build());
	}
}

