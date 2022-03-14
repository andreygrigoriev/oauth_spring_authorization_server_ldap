package com.netcracker.oauth_spring_authorization_server_ldap.service;

import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUser;
import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUserPrincipal;
import com.netcracker.oauth_spring_authorization_server_ldap.repository.AppUserRepository;
import lombok.Data;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@ConditionalOnProperty(name = "auth.enabled", havingValue = "true", matchIfMissing = true)
@Service
public class UserDetailsDBService implements UserDetailsService {

   private final static String AUTH = "auth";

   private final AppUserRepository appUserRepository;

   @Configuration
   @ConfigurationProperties(prefix = AUTH)
   @Data
   static class AuthConfig {
      private Boolean enabled;
      private Boolean blockUserAfterFailedAttempts;
   }

   @Autowired
   public UserDetailsDBService(AppUserRepository appUserRepository) {
      this.appUserRepository = appUserRepository;
   }

   @Override
   public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException {
      return Optional.ofNullable(getUserByLoginId(userName))
            .map(AppUserPrincipal::new)
            .orElseThrow(() -> new UsernameNotFoundException("No user found with userName: " + userName));
   }

   private AppUser getUserByLoginId(String loginId) {
      return appUserRepository.findByLoginId(loginId);
   }
}
