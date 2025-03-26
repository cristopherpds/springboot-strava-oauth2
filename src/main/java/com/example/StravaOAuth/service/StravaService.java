package com.example.StravaOAuth.service;

import com.example.StravaOAuth.athletetoken.AthleteToken;
import com.example.StravaOAuth.athletetoken.TokenService;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.Collections;
import java.util.List;
import java.util.Map;

@Service
@RequiredArgsConstructor
@Slf4j
public class StravaService {

    private final TokenService tokenService;
    private final RestTemplate restTemplate;
    
    public Map<String, Object> getAthlete(Long athleteId) {
        AthleteToken token = tokenService.refreshTokenIfNeeded(athleteId);
        String url = "https://www.strava.com/api/v3/athlete";
        
        HttpHeaders headers = createAuthHeaders(token.getAccessToken());
        
        ResponseEntity<Map> response = restTemplate.exchange(
            url, 
            HttpMethod.GET, 
            new HttpEntity<>(headers), 
            Map.class
        );
        
        return response.getBody();
    }
    
    public List<Map<String, Object>> getActivities(Long athleteId, int page, int perPage) {
        AthleteToken token = tokenService.refreshTokenIfNeeded(athleteId);
        
        UriComponentsBuilder uriBuilder = UriComponentsBuilder
            .fromHttpUrl("https://www.strava.com/api/v3/athlete/activities")
            .queryParam("page", page)
            .queryParam("per_page", perPage);
        
        HttpHeaders headers = createAuthHeaders(token.getAccessToken());
        
        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
            uriBuilder.toUriString(),
            HttpMethod.GET,
            new HttpEntity<>(headers),
            new ParameterizedTypeReference<List<Map<String, Object>>>() {}
        );
        
        if (response.getBody() == null) {
            return Collections.emptyList();
        }
        
        return response.getBody();
    }
    
    private HttpHeaders createAuthHeaders(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.set("Authorization", "Bearer " + accessToken);
        return headers;
    }
}