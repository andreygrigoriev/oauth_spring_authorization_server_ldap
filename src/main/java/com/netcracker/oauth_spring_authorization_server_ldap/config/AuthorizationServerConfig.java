package com.netcracker.oauth_spring_authorization_server_ldap.config;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import com.fasterxml.jackson.annotation.*;
import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUser;
import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUserPrincipal;

import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.jwt.JoseHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationContext;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration(proxyBeanMethods = false)
@Order(2)
public class AuthorizationServerConfig {

   private final PasswordEncoder passwordEncoder;
   private final AuthProperties authProperties;
   private final UserDetailsService userDetailsService;

   private static final String AUTHORITIES_CLAIM = "authorities";

   @Autowired
   @SuppressWarnings("unused")
   public AuthorizationServerConfig(AuthProperties authProperties,
         PasswordEncoder passwordEncoder, @Qualifier("userDetailsDBService") UserDetailsService userDetailsService) {
      this.authProperties = authProperties;
      this.passwordEncoder = passwordEncoder;
      this.userDetailsService = userDetailsService;
   }

   @Bean
   @Order(1)
   @SuppressWarnings("unused")
   public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
      OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer<>();
      RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();

      // Custom User Info Mapper that retrieves claims from a signed JWT
      Function<OidcUserInfoAuthenticationContext, OidcUserInfo> userInfoMapper = context -> {
         OidcUserInfoAuthenticationToken authentication = context.getAuthentication();
         JwtAuthenticationToken principal = (JwtAuthenticationToken) authentication.getPrincipal();
         return new OidcUserInfo(principal.getToken().getClaims());
      };

      http
            .requestMatcher(endpointsMatcher)
            .authorizeRequests(authorizeRequests ->
                  authorizeRequests.anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
            .oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
            .apply(authorizationServerConfigurer)
            .oidc(oidc -> oidc
                  .clientRegistrationEndpoint(Customizer.withDefaults())
                  .userInfoEndpoint(userInfo -> userInfo.userInfoMapper(userInfoMapper))
            )
      ;

      return http
            .formLogin(Customizer.withDefaults()).build();
   }

   @Bean
   @SuppressWarnings("unused")
   public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
      RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(authProperties.clientId)
            .clientSecret(passwordEncoder.encode(authProperties.clientSecret))
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri(authProperties.redirectUri)
            .redirectUri("https://localhost:8086/login/custom")
            .redirectUri("https://127.0.0.1:8086/login/custom")
            .redirectUri("https://127.0.0.1:8086/login/oauth2/code/custom")
            .scope(OidcScopes.OPENID)
            .scope("read")
            .scope("write")
            .scope("user_info")
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
            .build();

      // Save registered client in db as if in-memory
      JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
      registeredClientRepository.save(registeredClient);

      return registeredClientRepository;
   }

   @Bean
   @SuppressWarnings("unused")
   OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
      return context -> {
         JoseHeader.Builder headers = context.getHeaders();
         JwtClaimsSet.Builder claims = context.getClaims();
         OAuth2Authorization authorization = context.get(OAuth2Authorization.class);
         RegisteredClient registeredClient = context.get(RegisteredClient.class);
         OAuth2AuthorizationCodeAuthenticationToken authorizationCodeAuthentication =
               context.get(OAuth2AuthorizationCodeAuthenticationToken.class);

         Authentication principal = context.getPrincipal();
         Set<String> authorities = principal.getAuthorities().stream()
               .map(GrantedAuthority::getAuthority)
               .collect(Collectors.toSet());
         context.getClaims().claim(AUTHORITIES_CLAIM, authorities);

         claims.claim("tratata", "12345");

         Set<String> authorizedScopes = context.getAuthorizedScopes();
         Authentication authentication = context.getAuthorizationGrant();

         // TODO Customize

      };
   }

   @Bean
   @SuppressWarnings("unused")
   public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
      JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
      jdbcOAuth2AuthorizationService.setAuthorizationRowMapper(new RowMapper(registeredClientRepository));
      return jdbcOAuth2AuthorizationService;
   }

   @Bean
   @SuppressWarnings("unused")
   public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
      return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
   }

   static class RowMapper extends JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper {
      RowMapper(RegisteredClientRepository registeredClientRepository) {
         super(registeredClientRepository);
//         Hibernate5Module hibernate5Module = new Hibernate5Module();
//         getObjectMapper().registerModule(hibernate5Module);
         getObjectMapper().addMixIn(AppUserPrincipal.class, AppUserPrincipalMixin.class);
         getObjectMapper().addMixIn(AppUser.class, AppUserMixin.class);
      }
   }

   @Bean
   @SuppressWarnings("unused")
   public DaoAuthenticationProvider daoAuthenticationProvider() {
      DaoAuthenticationProvider authProvider
            = new DaoAuthenticationProvider();
      authProvider.setUserDetailsService(userDetailsService);
      authProvider.setPasswordEncoder(passwordEncoder);
      return authProvider;
   }

   @Bean
   @SuppressWarnings("unused")
   public OAuth2ClientAuthenticationProvider oauthClientAuthProvider(RegisteredClientRepository registeredClientRepository, OAuth2AuthorizationService oAuth2AuthorizationService) {
      OAuth2ClientAuthenticationProvider clientAuthenticationProvider =
            new OAuth2ClientAuthenticationProvider(
                  registeredClientRepository,
                  oAuth2AuthorizationService);
      clientAuthenticationProvider.setPasswordEncoder(passwordEncoder);
      return clientAuthenticationProvider;
   }

   @Bean
   @SuppressWarnings("unused")
   public ProviderSettings providerSettings() {
      return ProviderSettings.builder().issuer(authProperties.getIssuerUri()).build();
   }

   @Bean
   @SuppressWarnings("unused")
   public AuthenticationManager authManagerBean(List<AuthenticationProvider> providers) {
      return new ProviderManager(providers);
   }

   @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
   @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
         isGetterVisibility = JsonAutoDetect.Visibility.NONE)
   @JsonIgnoreProperties(ignoreUnknown = true)
   @SuppressWarnings("unused")
   static class AppUserPrincipalMixin {
      @JsonCreator
      public AppUserPrincipalMixin(@JsonProperty("user") AppUser user) {
      }
   }

   @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
   @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE,
         isGetterVisibility = JsonAutoDetect.Visibility.NONE)
   @JsonIgnoreProperties(value = "templateIds", ignoreUnknown = true)
   @SuppressWarnings("unused")
   static class AppUserMixin {
      @JsonCreator
//   public AppUserMixin(@JsonProperty("id") UUID id, @JsonProperty("loginId") String loginId, @JsonProperty("templateIds") List<UUID> templateIds) {
      public AppUserMixin(@JsonProperty("id") UUID id, @JsonProperty("loginId") String loginId) {
      }
   }

   @Configuration
   @ConfigurationProperties(prefix = "auth")
   @Data
   static class AuthProperties {
      private long accessTokenValidity;
      private long refreshTokenValidity;
      private String issuerUri;
      private String clientId;
      private String clientSecret;
      private String redirectUri;
   }
}