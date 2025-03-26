package com.example.StravaOAuth.config;

import com.example.StravaOAuth.athletetoken.AthleteToken;
import com.example.StravaOAuth.athletetoken.AthleteTokenRepository;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
@Slf4j
public class OAuth2SuccessHandler {

    private final AthleteTokenRepository athleteTokenRepository;

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        if (event.getAuthentication() instanceof OAuth2AuthenticationToken) {
            OAuth2AuthenticationToken authentication = (OAuth2AuthenticationToken) event.getAuthentication();
            
            if ("strava".equals(authentication.getAuthorizedClientRegistrationId())) {
                DefaultOAuth2User principal = (DefaultOAuth2User) authentication.getPrincipal();
                Map<String, Object> attributes = principal.getAttributes();
                
                // Extraer ID del atleta
                Long athleteId = ((Number) attributes.get("id")).longValue();
                
                log.info("Strava OAuth2 authentication successful for athlete ID: {}", athleteId);
                
                // Buscar token existente o crear uno nuevo
                Optional<AthleteToken> existingToken = athleteTokenRepository.findByStravaAthleteId(athleteId);
                
                if (existingToken.isPresent()) {
                    log.info("Token already exists for athlete ID: {}", athleteId);
                    // Aquí podrías actualizar el token existente si fuera necesario
                } else {
                    log.info("Creating new token for athlete ID: {}", athleteId);
                    
                    // En un evento de autenticación exitosa, no tenemos acceso directo al token
                    // Esta es una implementación básica para registrar que el usuario se autenticó
                    AthleteToken token = AthleteToken.builder()
                        .stravaAthleteId(athleteId)
                        .accessToken("oauth_managed_by_spring_security")
                        .refreshToken("oauth_managed_by_spring_security")
                        .expiresAt(Instant.now().plusSeconds(21600)) // 6 horas (ejemplo)
                        .tokenType("Bearer")
                        .scope("profile:read_all")
                        .build();
                    
                    athleteTokenRepository.save(token);
                    log.info("Token saved for athlete ID: {}", athleteId);
                }
            }
        }
    }
}