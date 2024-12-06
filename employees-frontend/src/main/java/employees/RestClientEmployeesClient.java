package employees;

import lombok.AllArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.List;

import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;

/**
 * Muszáj volt saját implementációt írni, mert a GET híváshoz nem kell
 * a backenden autentikáció, a POST-hoz meg igen. Ha beállítottam a GET-nél
 * is a clientRegistrationId()-t a
 * .defaultRequest(request -> request.attributes(clientRegistrationId("keycloak")))
 * használatával, akkor a GET-nél is akart tokent lekérni, de nem tudott,
 * mert nem volt bejelentkezés.
 */
@Component
@AllArgsConstructor
public class RestClientEmployeesClient implements EmployeesClient {

    private final RestClient restClient;

    @Override
    public List<Employee> listEmployees() {
        return restClient.get().uri("/api/employees").retrieve().body(
                new ParameterizedTypeReference<List<Employee>>() {}
        );
    }

    @Override
    public Employee createEmployee(Employee employee) {
        return restClient.post().uri("/api/employees").body(employee)
                .attributes(clientRegistrationId("keycloak"))
                .retrieve().body(
                Employee.class
        );
    }
}
