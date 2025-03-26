package com.example.StravaOAuth.athletetoken;

import com.example.StravaOAuth.service.StravaService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
@Slf4j
public class AthleteTokenController {

    private final TokenService tokenService;
    private final StravaService stravaService;
    private final AthleteTokenRepository athleteTokenRepository;

    @GetMapping("/callback")
    public ResponseEntity<String> authCallback(@RequestParam String code, @RequestParam String scope) {
        try {
            AthleteToken token = tokenService.saveTokenFromAuthCode(code);
            return ResponseEntity.ok("Authorization successful for athlete ID: " + token.getStravaAthleteId());
        } catch (Exception e) {
            log.error("Error during authorization callback", e);
            return ResponseEntity.badRequest().body("Authorization failed: " + e.getMessage());
        }
    }

    @GetMapping("/athlete")
    public Map<String, Object> getAthlete(@AuthenticationPrincipal OAuth2User principal) {
        Long athleteId = principal.getAttribute("id");
        return stravaService.getAthlete(athleteId);
    }

    @GetMapping("/activities")
    public List<Map<String, Object>> getActivities(
            @AuthenticationPrincipal OAuth2User principal,
            @RequestParam(defaultValue = "1") int page,
            @RequestParam(defaultValue = "30") int perPage) {
        Long athleteId = principal.getAttribute("id");
        return stravaService.getActivities(athleteId, page, perPage);
    }

    @GetMapping("/tokens")
    public List<AthleteToken> getAllTokens() {
        return athleteTokenRepository.findAll();
    }
}