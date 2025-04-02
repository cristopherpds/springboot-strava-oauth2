# Strava OAuth2 Integration Step by Step
![image](https://github.com/user-attachments/assets/c779d1c2-7b66-4d62-b604-e40582654501)
![image](https://github.com/user-attachments/assets/d703aaa0-9369-4545-bdb9-dd1a3ee5d235)
![image](https://github.com/user-attachments/assets/d693019a-81e2-4233-adff-4655096fc7f4)



Este Step by Step muestra cómo crear una aplicación Spring Boot que se integra con la API de Strava utilizando OAuth2 para autenticar a los usuarios y acceder a sus datos de actividad física.

## Índice
1. Requisitos Previos
2. Configuración de la Aplicación en Strava
3. Creación del Proyecto Spring Boot
4. Configuración de OAuth2
5. Configuración de Seguridad
6. Modelo de Datos y Repositorios
7. Servicio de Tokens
8. Servicio de Strava
9. Controladores
10. Interfaz de Usuario
11. Prueba de la Aplicación

## Requisitos Previos

- JDK 21 o superior
- Maven
- MySQL
- Cuenta en [Strava](https://www.strava.com/)
- IDE de desarrollo (VS Code, IntelliJ, etc.)

## Configuración de la Aplicación en Strava

1. Inicia sesión en [Strava](https://www.strava.com/)
2. Ve a [Strava Developers](https://developers.strava.com/) y crea una aplicación
3. Completa el formulario con la siguiente información:
   - **Application Name**: Nombre de tu aplicación
   - **Category**: Tipo de aplicación (por ejemplo, "Training Analysis")
   - **Club**: Opcional
   - **Website**: URL de tu sitio (puedes usar http://localhost:8080 para desarrollo)
   - **Application Description**: Descripción breve
   - **Authorization Callback Domain**: localhost

4. Después de crear la aplicación, toma nota del **Client ID** y el **Client Secret**

## Creación del Proyecto Spring Boot

1. Utiliza [Spring Initializr](https://start.spring.io/) para crear un nuevo proyecto con las siguientes dependencias:
   - Spring Web
   - Spring Security
   - OAuth2 Client
   - Spring Data JPA
   - MySQL Driver
   - Thymeleaf
   - Lombok

2. Descarga y descomprime el proyecto generado.

## Configuración de OAuth2

Configura la autenticación OAuth2 con Strava en el archivo `application.properties`:

```properties
spring.application.name=StravaOAuth

# Configuración de base de datos
spring.datasource.url=jdbc:mysql://localhost:3306/oauth
spring.datasource.username=root
spring.datasource.password=
spring.jpa.hibernate.ddl-auto=update
spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation=true

# Configuración de errores (útil para desarrollo)
server.error.include-message=always
server.error.include-exception=true
server.error.include-stacktrace=always
server.error.include-binding-errors=always

# Configuración de OAuth2 para Strava
spring.security.oauth2.client.registration.strava.client-id=TU_CLIENT_ID
spring.security.oauth2.client.registration.strava.client-secret=TU_CLIENT_SECRET
spring.security.oauth2.client.registration.strava.authorization-grant-type=authorization_code
spring.security.oauth2.client.registration.strava.scope=profile:read_all
spring.security.oauth2.client.registration.strava.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}
spring.security.oauth2.client.registration.strava.client-authentication-method=client_secret_post

# Endpoints de Strava para OAuth2
spring.security.oauth2.client.provider.strava.authorization-uri=https://www.strava.com/oauth/authorize
spring.security.oauth2.client.provider.strava.token-uri=https://www.strava.com/oauth/token
spring.security.oauth2.client.provider.strava.user-info-uri=https://www.strava.com/api/v3/athlete
spring.security.oauth2.client.provider.strava.user-name-attribute=id
```

## Configuración de Seguridad

Crea una clase `SecurityConfig` para configurar Spring Security:

```java
package com.example.StravaOAuth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        
        http
            .csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/error", "/webjars/**", "/css/**", "/js/**").permitAll()
                .anyRequest().authenticated()
            )
            .oauth2Login(oauth2 -> oauth2
                .defaultSuccessUrl("/", true)
                .loginPage("/login")
            )
            .logout(logout -> logout
                .logoutSuccessUrl("/login")
                .permitAll()
            );
        
        return http.build();
    }
}
```

## Modelo de Datos y Repositorios

Crea el modelo para almacenar tokens de acceso:

```java
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
```

Crea el repositorio JPA:

```java
package com.example.StravaOAuth.athletetoken;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface AthleteTokenRepository extends JpaRepository<AthleteToken, Long> {
    Optional<AthleteToken> findByStravaAthleteId(Long stravaAthleteId);
}
```

## Servicio de Tokens

Crea un servicio para manejar la obtención y renovación de tokens:

```java
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
```

## Servicio de Strava

Crea un servicio para interactuar con la API de Strava:

```java
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
```

## Controladores

Crea los controladores para manejar las solicitudes HTTP:

### HomeController

```java
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
        return "login";
    }

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
```

### AthleteTokenController

```java
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
```

## Interfaz de Usuario

### Login Page (login.html)

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Login with Strava</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }
        .login-container {
            max-width: 500px;
            width: 100%;
            padding: 30px;
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 {
            color: #FC4C02;
            margin-bottom: 20px;
        }
        .login-btn {
            display: inline-block;
            background-color: #FC4C02;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 4px;
            font-weight: bold;
            margin: 20px 0;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .login-btn:hover {
            background-color: #E34902;
            color: white;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h1>Conecta con Strava</h1>
        <p>Inicia sesión con tu cuenta de Strava para acceder a tus actividades y datos.</p>
        
        <a href="/oauth2/authorization/strava" class="login-btn">
            Conectar con Strava
        </a>
    </div>
</body>
</html>
```

### Dashboard Page (dashboard.html)

```html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>Dashboard de Strava</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            padding: 20px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            margin-bottom: 30px;
            border-bottom: 1px solid #ddd;
        }
        .header h1 {
            color: #FC4C02;
            margin: 0;
        }
        .profile-image {
            width: 100px;
            height: 100px;
            border-radius: 50%;
            object-fit: cover;
            border: 2px solid #FC4C02;
        }
        .info-card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            padding: 20px;
            margin-bottom: 20px;
        }
        .logout-btn {
            color: white;
            background-color: #FC4C02;
            text-decoration: none;
            font-weight: bold;
            padding: 8px 15px;
            border-radius: 4px;
        }
        .logout-btn:hover {
            background-color: #E34902;
            color: white;
        }
        .stat-badge {
            background-color: #FC4C02;
            color: white;
            border-radius: 4px;
            padding: 10px;
            text-align: center;
            margin-bottom: 15px;
        }
        .stat-value {
            font-size: 24px;
            font-weight: bold;
            display: block;
        }
        .nav-tabs .nav-link.active {
            color: #FC4C02;
            border-bottom: 2px solid #FC4C02;
        }
        .activity-item {
            border-left: 3px solid #FC4C02;
            padding-left: 15px;
            margin-bottom: 15px;
        }
        .activity-icon {
            font-size: 1.5rem;
            margin-right: 10px;
            color: #FC4C02;
        }
        .activity-date {
            color: #6c757d;
            font-size: 0.9rem;
        }
        #activityTypesChart, #weeklyDistanceChart {
            margin-top: 15px;
            height: 200px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Dashboard de Strava</h1>
            <div>
                <a href="https://www.strava.com/dashboard" target="_blank" class="btn btn-outline-secondary me-2">
                    <i class="bi bi-box-arrow-up-right"></i> Ir a Strava
                </a>
                <a href="/logout" class="logout-btn">
                    <i class="bi bi-box-arrow-right"></i> Cerrar sesión
                </a>
            </div>
        </div>
        
        <div class="row">
            <div class="col-md-4">
                <div class="info-card">
                    <div class="text-center mb-4">
                        <img th:src="${athlete.profile}" alt="Perfil" class="profile-image mb-3">
                        <h3 th:text="${athlete.firstname + ' ' + athlete.lastname}">Nombre del Atleta</h3>
                        <p th:text="${athlete.city + ', ' + athlete.country}">Ciudad, País</p>
                    </div>
                    
                    <div class="mb-1">
                        <i class="bi bi-gender-ambiguous"></i>
                        <strong>Género:</strong>
                        <span th:text="${athlete.sex == 'M' ? 'Masculino' : 'Femenino'}">Género</span>
                    </div>
                    
                    <div class="mb-1">
                        <i class="bi bi-star-fill"></i>
                        <strong>Cuenta Premium:</strong>
                        <span th:text="${athlete.premium ? 'Sí' : 'No'}">Premium</span>
                    </div>
                    
                    <div class="mb-1" th:if="${athlete.weight != null && athlete.weight > 0}">
                        <i class="bi bi-speedometer2"></i>
                        <strong>Peso:</strong>
                        <span th:text="${athlete.weight + ' kg'}">Peso</span>
                    </div>
                    
                    <hr>
                    
                    <h5 class="mt-3 mb-3">Resumen de Actividad</h5>
                    <div class="row">
                        <div class="col-6">
                            <div class="stat-badge">
                                <span class="stat-value" id="totalActivities">0</span>
                                <span>Actividades</span>
                            </div>
                        </div>
                        <div class="col-6">
                            <div class="stat-badge">
                                <span class="stat-value" id="totalDistance">0</span>
                                <span>km Totales</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="mt-3">
                        <canvas id="activityTypesChart"></canvas>
                    </div>
                </div>
            </div>
            
            <div class="col-md-8">
                <div class="info-card">
                    <h4>¡Bienvenido a tu Dashboard de Strava!</h4>
                    <p>Has conectado exitosamente tu cuenta de Strava. Desde aquí puedes ver tu información de perfil y actividades recientes.</p>
                    
                    <div class="alert alert-info mt-3">
                        <i class="bi bi-info-circle"></i> 
                        <strong>Nota:</strong> Esta aplicación utiliza OAuth 2.0 para conectar con Strava de forma segura.
                    </div>
                    
                    <div class="mt-4">
                        <canvas id="weeklyDistanceChart"></canvas>
                    </div>
                </div>
                
                <div class="info-card">
                    <ul class="nav nav-tabs" id="activityTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="recent-tab" data-bs-toggle="tab" data-bs-target="#recent" type="button" role="tab">
                                Actividades Recientes
                            </button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="stats-tab" data-bs-toggle="tab" data-bs-target="#stats" type="button" role="tab">
                                Estadísticas
                            </button>
                        </li>
                    </ul>
                    
                    <div class="tab-content mt-3" id="activityTabsContent">
                        <div class="tab-pane fade show active" id="recent" role="tabpanel">
                            <div id="activities-list">
                                <div class="d-flex justify-content-center">
                                    <div class="spinner-border text-primary" role="status">
                                        <span class="visually-hidden">Cargando...</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="tab-pane fade" id="stats" role="tabpanel">
                            <div class="row mt-3">
                                <div class="col-md-6 mb-2">
                                    <strong>ID de atleta:</strong>
                                    <span th:text="${athlete.id}">ID</span>
                                </div>
                                <div class="col-md-6 mb-2">
                                    <strong>Estado de la cuenta:</strong>
                                    <span th:text="${athlete.premium ? 'Premium' : 'Básica'}">Tipo</span>
                                </div>
                                <div class="col-md-6 mb-2">
                                    <strong>País:</strong>
                                    <span th:text="${athlete.country}">País</span>
                                </div>
                                <div class="col-md-6 mb-2">
                                    <strong>Ciudad:</strong>
                                    <span th:text="${athlete.city}">Ciudad</span>
                                </div>
                                
                                <div class="col-12 mt-4">
                                    <h5>Récords Personales</h5>
                                    <div id="personal-records">
                                        <div class="alert alert-secondary">
                                            Los récords personales se mostrarán aquí cuando estén disponibles.
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Fetch athlete activities
        fetch('/api/activities?page=1&perPage=10')
            .then(response => response.json())
            .then(activities => {
                if (activities.length === 0) {
                    document.getElementById('activities-list').innerHTML = '<div class="alert alert-info">No se encontraron actividades recientes</div>';
                    return;
                }
                
                let html = '';
                let totalDistance = 0;
                const activityTypes = {};
                const weeklyData = {};
                
                activities.forEach(activity => {
                    // Format activity data
                    const date = new Date(activity.start_date);
                    const formattedDate = date.toLocaleDateString('es-ES', { 
                        weekday: 'long', 
                        year: 'numeric', 
                        month: 'long', 
                        day: 'numeric' 
                    });
                    const distance = (activity.distance / 1000).toFixed(2);
                    const duration = formatDuration(activity.moving_time);
                    
                    // Sum up total distance
                    totalDistance += activity.distance / 1000;
                    
                    // Count activity types
                    activityTypes[activity.type] = (activityTypes[activity.type] || 0) + 1;
                    
                    // Group by week
                    const weekKey = getWeekNumber(date);
                    if (!weeklyData[weekKey]) {
                        weeklyData[weekKey] = 0;
                    }
                    weeklyData[weekKey] += activity.distance / 1000;
                    
                    // Choose icon based on activity type
                    let activityIcon = 'bi-activity';
                    if (activity.type === 'Run') {
                        activityIcon = 'bi-bicycle';
                    } else if (activity.type === 'Ride') {
                        activityIcon = 'bi-bicycle';
                    } else if (activity.type === 'Swim') {
                        activityIcon = 'bi-water';
                    } else if (activity.type === 'Walk') {
                        activityIcon = 'bi-person-walking';
                    }
                    
                    html += `
                        <div class="activity-item">
                            <div class="d-flex align-items-center">
                                <i class="${activityIcon} activity-icon"></i>
                                <div>
                                    <h5 class="mb-1">${activity.name}</h5>
                                    <div class="activity-date">${formattedDate}</div>
                                </div>
                            </div>
                            <div class="row mt-2">
                                <div class="col-4">
                                    <strong>${distance} km</strong><br>
                                    <small>Distancia</small>
                                </div>
                                <div class="col-4">
                                    <strong>${duration}</strong><br>
                                    <small>Duración</small>
                                </div>
                                <div class="col-4">
                                    <strong>${activity.total_elevation_gain || 0} m</strong><br>
                                    <small>Elevación</small>
                                </div>
                            </div>
                        </div>
                    `;
                });
                
                document.getElementById('activities-list').innerHTML = html;
                document.getElementById('totalActivities').textContent = activities.length;
                document.getElementById('totalDistance').textContent = totalDistance.toFixed(1);
                
                // Create activity types chart
                createActivityTypesChart(activityTypes);
                
                // Create weekly distance chart
                createWeeklyDistanceChart(weeklyData);
            })
            .catch(error => {
                console.error('Error fetching activities:', error);
                document.getElementById('activities-list').innerHTML = '<div class="alert alert-danger">Error al cargar actividades</div>';
            });
            
        function formatDuration(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            
            return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
        }
        
        function getWeekNumber(date) {
            const firstDayOfYear = new Date(date.getFullYear(), 0, 1);
            const pastDaysOfYear = (date - firstDayOfYear) / 86400000;
            return Math.ceil((pastDaysOfYear + firstDayOfYear.getDay() + 1) / 7);
        }
        
        function createActivityTypesChart(activityTypes) {
            const ctx = document.getElementById('activityTypesChart').getContext('2d');
            
            const data = {
                labels: Object.keys(activityTypes),
                datasets: [{
                    data: Object.values(activityTypes),
                    backgroundColor: [
                        '#FC4C02', 
                        '#1E88E5', 
                        '#43A047', 
                        '#FFB300',
                        '#8E24AA'
                    ],
                    borderWidth: 1
                }]
            };
            
            new Chart(ctx, {
                type: 'doughnut',
                data: data,
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'bottom',
                        },
                        title: {
                            display: true,
                            text: 'Tipos de Actividad'
                        }
                    }
                }
            });
        }
        
        function createWeeklyDistanceChart(weeklyData) {
            const ctx = document.getElementById('weeklyDistanceChart').getContext('2d');
            
            // Sort weeks
            const sortedWeeks = Object.keys(weeklyData).sort((a, b) => a - b);
            const labels = sortedWeeks.map(week => `Semana ${week}`);
            const distances = sortedWeeks.map(week => weeklyData[week]);
            
            const data = {
                labels: labels,
                datasets: [{
                    label: 'Distancia (km)',
                    data: distances,
                    backgroundColor: 'rgba(252, 76, 2, 0.2)',
                    borderColor: '#FC4C02',
                    borderWidth: 2,
                    tension: 0.4
                }]
            };
            
            new Chart(ctx, {
                type: 'line',
                data: data,
                options: {
                    responsive: true,
                    plugins: {
                        title: {
                            display: true,
                            text: 'Distancia por Semana (km)'
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    </script>
</body>
</html>
```

## Configuración del RestTemplate

Crea un bean para el RestTemplate:

```java
package com.example.StravaOAuth.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}
```

## Prueba de la Aplicación

1. Asegúrate de tener MySQL en ejecución con una base de datos llamada "oauth"
2. Inicia la aplicación con `mvn spring-boot:run`
3. Accede a `http://localhost:8080` en tu navegador
4. Haz clic en "Conectar con Strava" para iniciar el flujo de autenticación
5. Después de la autenticación exitosa, serás redirigido al dashboard con tus datos

## Consideraciones Adicionales

- **Seguridad**: Protege tus credenciales client_id y client_secret. Considera usar variables de entorno o almacenamiento seguro.
- **Rate Limiting**: Strava tiene límites de tasa para las API. Consulta la [documentación oficial](https://developers.strava.com/docs/rate-limits/).
- **Refreshing Tokens**: Los tokens de acceso expiran, así que la implementación incluye renovación automática.
- **Manejo de Errores**: Implementa un manejo de errores robusto para casos como tokens inválidos, errores de API, etc.

## Recursos y Documentación

- [Documentación de la API de Strava](https://developers.strava.com/docs/reference/)
- [OAuth 2.0 en Spring Security](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
- [Guía OAuth 2.0 Client](https://docs.spring.io/spring-security/reference/servlet/oauth2/client/index.html)
- [Proyecto correlato](https://github.com/JinpaLhawang/strava-oauth2)
---

Este Step by Step proporciona una base sólida para integrar Strava OAuth2 en una aplicación Spring Boot. Puedes ampliar esta implementación agregando más funcionalidades de Strava como:

- Análisis detallado de actividades
- Seguimiento de metas de entrenamiento
- Comparación de rendimiento
- Visualización de mapas de actividades
