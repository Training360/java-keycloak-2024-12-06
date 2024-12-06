package employees;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.*;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, ClientRegistrationRepository repo) throws Exception {
        var baseUri = OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(repo, baseUri);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http
                .authorizeHttpRequests(registry -> registry
                                .requestMatchers( "/create-employee")
                                .hasRole("employees_admin")
                                .anyRequest()
                                .permitAll()
                        )
                .oauth2Login(customizer -> customizer.authorizationEndpoint(config -> config.authorizationRequestResolver(resolver)))
                .logout(logout -> logout
                        .logoutSuccessHandler(oidcLogoutSuccessHandler(repo))
                );
        return http.build();
    }

    private LogoutSuccessHandler oidcLogoutSuccessHandler(ClientRegistrationRepository repo) {
        OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
                new OidcClientInitiatedLogoutSuccessHandler(repo);

        // Sets the location that the End-User's User Agent will be redirected to
        // after the logout has been performed at the Provider
        oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");

        return oidcLogoutSuccessHandler;
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return authorities -> authorities.stream().flatMap(authority -> {
            switch (authority) {
                case OidcUserAuthority oidcUserAuthority -> {
                    var realmAccess = (Map<String, Object>) oidcUserAuthority.getAttributes().get("realm_access");
                    var roles = (List<String>) realmAccess.get("roles");


                    //                    OidcIdToken idToken = oidcUserAuthority.getIdToken();
                    //                    OidcUserInfo userInfo = oidcUserAuthority.getUserInfo();

                    // Map the claims found in idToken and/or userInfo
                    // to one or more GrantedAuthority's and add it to mappedAuthorities
                    return roles.stream()
                            .map(roleName -> "ROLE_" + roleName)
                            .map(SimpleGrantedAuthority::new);


                }
                case OAuth2UserAuthority oauth2UserAuthority -> {
                    Map<String, Object> userAttributes = oauth2UserAuthority.getAttributes();

                    // Map the attributes found in userAttributes
                    // to one or more GrantedAuthority's and add it to mappedAuthorities
                    return Stream.of();
                }
                case SimpleGrantedAuthority simpleGrantedAuthority -> {
                    return Stream.of(simpleGrantedAuthority);
                }
                default ->
                    throw new IllegalStateException("Invalid authority: %s".formatted(authority.getClass().getName()));

            }
        }).toList();
    }

}
