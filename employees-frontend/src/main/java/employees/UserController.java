package employees;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.ModelAndView;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping
@AllArgsConstructor
@Slf4j
public class UserController {

    private Environment environment;

    @GetMapping("/user")
    public ModelAndView index() {
        Map<String, Object> model = new HashMap<>();

        return new ModelAndView("user", model);
    }

    @GetMapping("/account-console")
    public String accountConsole() {
        return "redirect:" +  getAuthServerFrontendUrl() + "/account";
    }

    private String getAuthServerFrontendUrl() {
        String prefix = environment.getProperty("employees-ui.auth-server-frontend-url");
        String realm = environment.getProperty("keycloak.realm");
        String url = prefix + "/realms/" + realm;
        return url;
    }

}
