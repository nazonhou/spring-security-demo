package bj.nazonhou.springsecuritydemystified;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class Controller {
    @GetMapping("/public")
    public String opened() {
        return String.format("Public endpoint 🎉");
    }

    @GetMapping("/private")
    public String closed(Authentication authentication) {
        if (ServerAuthentication.class.isAssignableFrom(authentication.getClass())) {
            ServerAuthentication serverAuthentication = (ServerAuthentication) authentication;
            return "Welcome " + serverAuthentication.getPrincipal();
        }
        return String.format("Private endpoint 🚦");
    }
}
