package com.example.StravaOAuth;


import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class HomeController {

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OAuth2User principal, Model model) {
        // Si el usuario está autenticado, mostrar el dashboard
        if (principal != null) {
            Map<String, Object> attributes = principal.getAttributes();
            
            if (attributes.containsKey("athlete")) {
                model.addAttribute("athlete", attributes.get("athlete"));
            } else {
                model.addAttribute("athlete", attributes);
            }
            
            return "dashboard";
        }
        
        // Si no está autenticado, mostrar directamente la página de login
        return "login";  // No usamos redirect, cargamos directamente la vista login.html
    }

    // Si ya tienes este método, puedes dejarlo, pero no es estrictamente necesario
    @GetMapping("/login")
    public String login() {
        return "login";
    }
    
    @GetMapping("/userinfo")
    @ResponseBody
    public String userInfo(@AuthenticationPrincipal OAuth2User principal) {
        if (principal != null) {
            return "Logged in as: " + principal.getName() + "<br>" +
                  "Attributes: " + principal.getAttributes();
        }
        return "Not logged in";
    }
}
