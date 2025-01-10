package com.mildo.user;

import com.mildo.user.Vo.UserVO;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.view.RedirectView;

import java.util.Date;
import java.util.Map;

import static com.mildo.user.Auth.JwtTokenProvider.getExpirationFromToken;

@Slf4j
@Controller
@RequiredArgsConstructor
public class HomeController {

    private final UserService userService;

    @GetMapping("/home")
    public RedirectView home(@AuthenticationPrincipal OidcUser principal) {
        UserVO user = userService.login(principal);
        String userId = user.getUserId();
        String social = "google";
        String redirectUrl = "http://mildo.xyz/social-login/" + social + "?userId=" + userId;
        return new RedirectView(redirectUrl);
    }

    @GetMapping("/llogin")
    public RedirectView home() {
        String redirectUrl = "/oauth2/authorization/google";
        return new RedirectView(redirectUrl);
    }

    @GetMapping("/login-failed")
    public RedirectView faillLogin(){
        String redirectUrl = "http://mildo.xyz";
        return new RedirectView(redirectUrl);
    }


}
