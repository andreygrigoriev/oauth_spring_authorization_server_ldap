package com.netcracker.oauth_spring_authorization_server_ldap.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwsEncoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
@Order(1)
public class OauthConfig {
   @Bean
   @SuppressWarnings("unused")
   public JWKSource<SecurityContext> jwkSource(@Qualifier("jwtRsaKeyPair") RSAKey rsaKeyPair) {
      return (jwkSelector, securityContext) -> jwkSelector.select(new JWKSet(rsaKeyPair));
   }

   @Bean
   @SuppressWarnings("unused")
   public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
      return new NimbusJwsEncoder(jwkSource);
   }

   private KeyPair generateRsaKeyPair() {
      KeyPair keyPair;
      try {
         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
         keyPairGenerator.initialize(2048);
         keyPair = keyPairGenerator.generateKeyPair();
      } catch (Exception ex) {
         throw new IllegalStateException(ex);
      }
      return keyPair;
   }

   @Bean(name = "jwtRsaKeyPair")
   @SuppressWarnings("unused")
   public RSAKey generateRsa() {
      KeyPair keyPair = generateRsaKeyPair();
      return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
            .privateKey((RSAPrivateKey) keyPair.getPrivate())
            .keyUse(KeyUse.SIGNATURE)
            .keyID(UUID.randomUUID().toString())
            .build();
   }

   @Bean
   @SuppressWarnings("unused")
   public BCryptPasswordEncoder passwordEncoder() {
      return new BCryptPasswordEncoder();
   }
}
