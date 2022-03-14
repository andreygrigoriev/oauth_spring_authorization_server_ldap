package com.netcracker.oauth_spring_authorization_server_ldap.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
public class ResourceServerConfig {

   private static final String AUTH_HEADER = "Authorization";

   @Bean
   @Order(4)
   @SuppressWarnings("unused")
   public SecurityFilterChain resourceServerOauthFilterChain(HttpSecurity http) throws Exception {
      return http
            .requestMatcher(createRequestMatcher(false))
            .authorizeRequests()
            .antMatchers("/actuator/health").permitAll()
            .antMatchers("/actuator/caches").permitAll()
            .antMatchers("/actuator/bohealth").permitAll()
            .antMatchers("/rest/**").authenticated()
            .and().csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .oauth2ResourceServer()
            .jwt(Customizer.withDefaults())
            .and().build();
   }

   @Bean
   @Order(5)
   @SuppressWarnings("unused")
   public SecurityFilterChain defaultFilterChain(HttpSecurity http) throws Exception {
      return http
            .csrf().disable()
            .authorizeRequests(authorizeRequests ->
                  authorizeRequests.anyRequest().authenticated()
            )
            .formLogin(Customizer.withDefaults())
            .build();
   }

   @Bean
   @SuppressWarnings("unused")
   public JwtDecoder jwtDecoder(@Value("${auth.jwks-uri}") String jwksUri) {
      return NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
   }

   private RequestMatcher createRequestMatcher(boolean isBasic) {
      RequestMatcher headerMatcher = request -> {
         String headerValue = request.getHeader(AUTH_HEADER);
         if (isBasic) {
            return headerValue != null && headerValue.startsWith("Basic");
         } else {
            return headerValue == null || !headerValue.startsWith("Basic");
         }
      };

      RequestMatcher actuatorMatcher = new AntPathRequestMatcher("/actuator/**");
      RequestMatcher ssoMatcher = new AntPathRequestMatcher("/sso/**");
      RequestMatcher restMatcher = new AntPathRequestMatcher("/rest/nc-extension/v1/**");

      RequestMatcher orRequestMatcher = new OrRequestMatcher(actuatorMatcher, ssoMatcher, restMatcher);

      return new AndRequestMatcher(headerMatcher, orRequestMatcher);
   }
}

