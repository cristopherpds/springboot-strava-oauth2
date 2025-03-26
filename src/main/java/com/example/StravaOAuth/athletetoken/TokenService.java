package com.example.StravaOAuth.athletetoken;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final AthleteTokenRepository athleteTokenRepository;
    private final RestTemplate restTemplate;
    
    @Value("${spring.security.oauth2.client.registration.strava.client-id}")
    private String clientId;
    
    @Value("${spring.security.oauth2.client.registration.strava.client-secret}")
    private String clientSecret;
    
    public AthleteToken saveTokenFromAuthCode(String code) {
        String tokenUrl = "https://www.strava.com/oauth/token";
        
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("code", code);
        requestBody.add("grant_type", "authorization_code");
        
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, requestBody, Map.class);
        Map<String, Object> tokenResponse = response.getBody();
        
        Map<String, Object> athlete = (Map<String, Object>) tokenResponse.get("athlete");
        Long athleteId = ((Number) athlete.get("id")).longValue();
        
        AthleteToken token = AthleteToken.builder()
            .stravaAthleteId(athleteId)
            .accessToken((String) tokenResponse.get("access_token"))
            .refreshToken((String) tokenResponse.get("refresh_token"))
            .expiresAt(Instant.ofEpochSecond(((Number) tokenResponse.get("expires_at")).longValue()))
            .tokenType((String) tokenResponse.get("token_type"))
            .scope((String) tokenResponse.get("scope"))
            .build();
        
        return athleteTokenRepository.save(token);
    }
    
    public AthleteToken refreshTokenIfNeeded(Long athleteId) {
        Optional<AthleteToken> tokenOpt = athleteTokenRepository.findByStravaAthleteId(athleteId);
        
        if (tokenOpt.isEmpty()) {
            throw new RuntimeException("No token found for athlete: " + athleteId);
        }
        
        AthleteToken token = tokenOpt.get();
        
        // Check if token is expired or will expire in the next hour
        if (token.getExpiresAt().isBefore(Instant.now().plusSeconds(3600))) {
            return refreshToken(token);
        }
        
        return token;
    }
    
    private AthleteToken refreshToken(AthleteToken token) {
        log.info("Refreshing token for athlete: {}", token.getStravaAthleteId());
        String tokenUrl = "https://www.strava.com/oauth/token";
        
        MultiValueMap<String, String> requestBody = new LinkedMultiValueMap<>();
        requestBody.add("client_id", clientId);
        requestBody.add("client_secret", clientSecret);
        requestBody.add("refresh_token", token.getRefreshToken());
        requestBody.add("grant_type", "refresh_token");
        
        ResponseEntity<Map> response = restTemplate.postForEntity(tokenUrl, requestBody, Map.class);
        Map<String, Object> tokenResponse = response.getBody();
        
        token.setAccessToken((String) tokenResponse.get("access_token"));
        token.setRefreshToken((String) tokenResponse.get("refresh_token"));
        token.setExpiresAt(Instant.ofEpochSecond(((Number) tokenResponse.get("expires_at")).longValue()));
        
        return athleteTokenRepository.save(token);
    }
}