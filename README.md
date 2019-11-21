# spring-security-oauth2-authorization-server
Demo Authorization Server using Nimbus and Spring Security

Before using, make sure to modify your `/etc/hosts` file so that you don't have problems with session cookies from a client app fighting with the authorization server.

```bash
127.0.0.1   idp
```

This is a Spring Boot application, so to start it, you can do:

```bash
gw :bootRun
```

To check that it is up, you can hit the OIDC discovery endpoint:

```bash
http :8081/.well-known/openid-configuration
```

The server has one client whose client id and secret are `client/secret`.

It has one user whose username and password are `user/password`.

It has three scopes, `profile`, `message:read`, and `message:write`.

#### Client Configuration

Now, configure a client application to point at this authorization server:

```bash
http --from https://start.spring.io/starter.tgz \
  dependencies=web,oauth2-client baseDir=client | tar -xzvf -
```

Modifying the `application.yml` like so:

```yaml
spring:
  security:
    oauth2:
      client:
        provider:
          keycloak:
            issuer-uri: http://idp:8081
        registration:
          keycloak:
            client-id: client
            client-secret: secret
```

Make sure to add some kind of endpoint:

```java
@RestController
public class ClientController {

	@GetMapping("/")
	public String index(Model model,
						@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
						@AuthenticationPrincipal OAuth2User oauth2User) {
		return oauth2User.getName();
	}
}
```

And you should see the name of the user: `user`.