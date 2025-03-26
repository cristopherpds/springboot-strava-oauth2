package com.example.StravaOAuth.config;

import com.example.StravaOAuth.athletetoken.AthleteToken;
import com.example.StravaOAuth.athletetoken.AthleteTokenRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;


import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class JpaOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private final AthleteTokenRepository athleteTokenRepository;

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        log.info("Loading authorized client for registration ID: {} and principal: {}", clientRegistrationId, principalName);
        // Implementación para cargar el cliente autorizado
        return null; // Spring OAuth2 gestiona esto en memoria
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        if ("strava".equals(authorizedClient.getClientRegistration().getRegistrationId()) && 
            principal instanceof OAuth2AuthenticationToken) {
            
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) principal;
            String userId = oauthToken.getName();
            
            Long athleteId = Long.parseLong(userId);
            log.info("Saving authorized client for Strava athlete ID: {}", athleteId);
            
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            
            // Buscar token existente o crear uno nuevo
            Optional<AthleteToken> existingTokenOpt = athleteTokenRepository.findByStravaAthleteId(athleteId);
            
            AthleteToken token;
            if (existingTokenOpt.isPresent()) {
                token = existingTokenOpt.get();
                log.info("Updating existing token for athlete ID: {}", athleteId);
            } else {
                token = new AthleteToken();
                token.setStravaAthleteId(athleteId);
                log.info("Creating new token for athlete ID: {}", athleteId);
            }
            
            // Actualizar información del token
            token.setAccessToken(accessToken.getTokenValue());
            token.setTokenType(accessToken.getTokenType().getValue());
            token.setExpiresAt(accessToken.getExpiresAt());
            
            if (refreshToken != null) {
                token.setRefreshToken(refreshToken.getTokenValue());
            }
            
            token.setScope(String.join(" ", accessToken.getScopes()));
            
            athleteTokenRepository.save(token);
            log.info("Token saved successfully for athlete ID: {}", athleteId);
        }
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        log.info("Removing authorized client for registration ID: {} and principal: {}", clientRegistrationId, principalName);
        if ("strava".equals(clientRegistrationId)) {
            try {
                Long athleteId = Long.parseLong(principalName);
                athleteTokenRepository.findByStravaAthleteId(athleteId)
                    .ifPresent(token -> {
                        athleteTokenRepository.delete(token);
                        log.info("Token removed for athlete ID: {}", athleteId);
                    });
            } catch (NumberFormatException e) {
                log.error("Invalid athlete ID format: {}", principalName);
            }
        }
    }
}