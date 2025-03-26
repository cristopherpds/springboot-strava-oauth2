package com.example.StravaOAuth.athletetoken;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import java.time.Instant;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Data @Builder @NoArgsConstructor @AllArgsConstructor
public class AthleteToken {

  @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long athleteTokenId;
  
  private Long stravaAthleteId;
  private String accessToken;
  private String refreshToken;
  private Instant expiresAt;
  private String tokenType;
  private String scope;
}