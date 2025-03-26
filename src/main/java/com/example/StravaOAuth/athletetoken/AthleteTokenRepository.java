package com.example.StravaOAuth.athletetoken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AthleteTokenRepository extends JpaRepository<AthleteToken, Long> {
    Optional<AthleteToken> findByStravaAthleteId(Long stravaAthleteId);
}