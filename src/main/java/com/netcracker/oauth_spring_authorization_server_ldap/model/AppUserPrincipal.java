package com.netcracker.oauth_spring_authorization_server_ldap.model;

import com.fasterxml.jackson.annotation.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;

@Data
@NoArgsConstructor
//@JsonIgnoreProperties(ignoreUnknown = true)
public class AppUserPrincipal implements UserDetails, Serializable {


   public AppUser getUser() {
      return user;
   }

   public void setUser(AppUser user) {
      this.user = user;
   }

//   @JsonProperty("user")
   private AppUser user;

   public AppUserPrincipal(AppUser appUser) {
      this.user = appUser;
   }

   @Override
//   @JsonIgnore
   public Collection<? extends GrantedAuthority> getAuthorities() {
      return Collections.singletonList(new SimpleGrantedAuthority("ROLE_admin"));
   }

   @Override
//   @JsonIgnore
   public String getPassword() {
      return user.getPassword();
   }

   @Override
//   @JsonProperty("name")
   public String getUsername() {
      return user.getLoginId();
   }

   @Override
//   @JsonProperty("isAccountNonExpired")
   public boolean isAccountNonExpired() {
      return true;
   }

   @Override
//   @JsonProperty("isAccountNonLocked")
   public boolean isAccountNonLocked() {
      return true;
   }

   @Override
//   @JsonProperty("isCredentialsNonExpired")
   public boolean isCredentialsNonExpired() {
      return true;
   }

   @Override
//   @JsonProperty("enabled")
   public boolean isEnabled() {
      return "active".equals(user.getStatus());
   }
}
