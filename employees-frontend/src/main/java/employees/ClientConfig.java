package employees;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientAdapter;
import org.springframework.web.service.invoker.HttpServiceProxyFactory;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(EmployeesProperties.class)
public class ClientConfig {
//    @Bean
//    public EmployeesClient employeesClient(RestClient.Builder builder, EmployeesProperties employeesProperties, OAuth2AuthorizedClientManager authorizedClientManager) {
//        var requestInterceptor =
//                new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);
//
//        var client = builder
//                .baseUrl(employeesProperties.getBackendUrl())
//                .requestInterceptor(requestInterceptor)
//                .build();
//
//        var factory = HttpServiceProxyFactory.builderFor(
//                RestClientAdapter.create(client)).build();
//
//        return factory.createClient(EmployeesClient.class);
//    }

    @Bean
    public RestClient restClient(RestClient.Builder builder, EmployeesProperties employeesProperties, OAuth2AuthorizedClientManager authorizedClientManager) {
        var requestInterceptor =
                new OAuth2ClientHttpRequestInterceptor(authorizedClientManager);

        return builder
                .baseUrl(employeesProperties.getBackendUrl())
                .requestInterceptor(requestInterceptor)
                .build();
    }
}
