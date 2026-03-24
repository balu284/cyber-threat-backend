package com.cyberthreat.config;

import com.cyberthreat.filter.JwtAuthenticationFilter;
import com.cyberthreat.service.JwtService;
import com.cyberthreat.service.OAuth2UserService;
import com.cyberthreat.service.UserService;

import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private OAuth2UserService oAuth2UserService;
    
    @Autowired
    private JwtService jwtService;

    @Value("${app.frontend.url}")
    private String frontendUrl;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider(UserService userService) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:4200"));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Content-Type"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, UserService userService) throws Exception {

        http
            .cors(cors -> cors.configurationSource(corsConfigurationSource()))
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authenticationProvider(authenticationProvider(userService))

            .oauth2Login(oauth2 -> oauth2
                .userInfoEndpoint(userInfo -> userInfo.userService(oAuth2UserService))
                .successHandler((request, response, authentication) -> {
                    OAuth2User oauthUser = (OAuth2User) authentication.getPrincipal();
                    String email = oauthUser.getAttribute("email");
                    String jwt = jwtService.generateToken(email);
                    response.sendRedirect(frontendUrl + "/auth/oauth2/success?token=" + jwt);
                })
                .failureHandler((request, response, exception) -> {
                    response.sendRedirect(frontendUrl + "/auth/login?error=true");
                })
            )

            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)

            .authorizeHttpRequests(auth -> auth
                // Allow preflight
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()

                // Auth APIs
                .requestMatchers("/api/auth/**").permitAll()
                
                // OAUTH2 ENDPOINTS
                .requestMatchers("/oauth2/**").permitAll()
                .requestMatchers("/login/oauth2/**").permitAll()

                // AGENT & DEVICE REGISTRATION
                .requestMatchers("/api/agent/**").permitAll()
                .requestMatchers("/api/devices/register").permitAll()

                // Public APIs
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/api/threat-intelligence/**").permitAll()
                .requestMatchers("/api/threats/**").permitAll()

                // ✅ FIXED - GMAIL CALLBACK MUST BE PUBLIC
                .requestMatchers("/api/gmail/callback").permitAll()
                .requestMatchers("/api/gmail/callback/**").permitAll()
                
                // ✅ Other Gmail endpoints require authentication
                .requestMatchers("/api/gmail/status").authenticated()
                .requestMatchers("/api/gmail/sessions/**").authenticated()
                .requestMatchers("/api/gmail/auth-url").authenticated()
                .requestMatchers("/api/gmail/disconnect").authenticated()

                // WebSocket
                .requestMatchers(
                        "/ws-threat-intel/**",
                        "/ws/**",
                        "/topic/**",
                        "/queue/**",
                        "/app/**"
                ).permitAll()

                // Swagger
                .requestMatchers(
                        "/v3/api-docs/**",
                        "/swagger-ui/**",
                        "/swagger-ui.html"
                ).permitAll()

                // Admin
                .requestMatchers("/api/admin/**").hasRole("ADMIN")

                // Everything else secured
                .anyRequest().authenticated()
            )
            
            // Add this to handle authentication errors properly
            .exceptionHandling(handling -> handling
                .authenticationEntryPoint((request, response, authException) -> {
                    // Don't block the callback endpoint
                    if (request.getRequestURI().contains("/api/gmail/callback")) {
                        response.setStatus(HttpServletResponse.SC_OK);
                        return;
                    }
                    response.setContentType("application/json");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write("{\"error\":\"Unauthorized\", \"message\":\"" + authException.getMessage() + "\"}");
                })
            );

        return http.build();
    }
}