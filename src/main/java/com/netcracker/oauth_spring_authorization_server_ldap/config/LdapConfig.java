package com.netcracker.oauth_spring_authorization_server_ldap.config;

import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUser;
import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUserPrincipal;
import com.netcracker.oauth_spring_authorization_server_ldap.repository.AppUserRepository;
import lombok.Data;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.AbstractLdapAuthenticator;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsMapper;
import org.springframework.util.CollectionUtils;

import java.util.*;

@Configuration(proxyBeanMethods = false)
@ConditionalOnExpression("!T(org.springframework.util.StringUtils).isEmpty('${application.ldap.url:}')")
public class LdapConfig {

   private final UserDetailsService userDetailsService;
   private final LdapProperties ldapProperties;
   private final AppUserRepository appUserRepository;

   @Autowired
   public LdapConfig(@Qualifier("userDetailsDBService") UserDetailsService userDetailsService,
         LdapProperties ldapProperties, AppUserRepository appUserRepository) {
      this.userDetailsService = userDetailsService;
      this.ldapProperties = ldapProperties;
      this.appUserRepository = appUserRepository;
   }

   @Bean
   public LdapAuthenticationProvider ldapAuthenticationProvider() {
      BaseLdapPathContextSource contextSource = contextSource();
      AbstractLdapAuthenticator ldapAuthenticator = new BindAuthenticator(contextSource);
      LdapUserSearch userSearch = new FilterBasedLdapUserSearch(ldapProperties.getUserSearchBase(), ldapProperties.getUserSearchFilter(), contextSource);
      ldapAuthenticator.setUserSearch(userSearch);
//      ldapAuthenticator.setUserDnPatterns(this.userDnPatterns);
      DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(
            contextSource, ldapProperties.getGroupSearchBase());
      authoritiesPopulator.setGroupRoleAttribute("cn");
      authoritiesPopulator.setGroupSearchFilter(ldapProperties.getGroupSearchFilter());
      authoritiesPopulator.setSearchSubtree(false);
      authoritiesPopulator.setRolePrefix("ROLE_");

      SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
      simpleAuthorityMapper.setPrefix("ROLE_");
      simpleAuthorityMapper.afterPropertiesSet();

      LdapAuthenticationProvider ldapAuthenticationProvider = new LdapAuthenticationProvider(ldapAuthenticator,
            authoritiesPopulator);
      ldapAuthenticationProvider.setAuthoritiesMapper(simpleAuthorityMapper);
      ldapAuthenticationProvider.setUserDetailsContextMapper(new LdapCustomUserMapper(appUserRepository, ldapProperties));

      return ldapAuthenticationProvider;
   }

   @Autowired
   @SuppressWarnings("unused")
   public void configureAuthentication(AuthenticationManagerBuilder auth) throws Exception {
      if (StringUtils.isNotEmpty(ldapProperties.getUrl())) {
         auth.authenticationProvider(ldapAuthenticationProvider());
      }
      //DB & preconfigured auth
//      auth.authenticationProvider(authenticationProvider());
      auth.userDetailsService(userDetailsService);
   }

   @Bean
   public BaseLdapPathContextSource contextSource() {
      DefaultSpringSecurityContextSource contextSource = new DefaultSpringSecurityContextSource(ldapProperties.getUrl().trim());
      contextSource.setUserDn(ldapProperties.getManagerDn().trim());
      contextSource.setPassword(ldapProperties.getManagerPassword().trim());
      contextSource.afterPropertiesSet();
      return contextSource;
   }

   static class LdapCustomUserMapper extends LdapUserDetailsMapper {
      private static final String FIRST_NAME = "firstName";
      private static final String LAST_NAME = "lastName";
      private static final String EMAIL = "email";
      private static final String DEFAULT_TEMPLATE_ID = "default";
      private final AppUserRepository appUserRepository;
      private final LdapProperties ldapProperties;

      @Autowired
      LdapCustomUserMapper(AppUserRepository appUserRepository, LdapProperties ldapProperties) {
         this.appUserRepository = appUserRepository;
         this.ldapProperties = ldapProperties;
      }

      @Override
      public UserDetails mapUserFromContext(DirContextOperations ctx, String username, Collection<? extends GrantedAuthority> authorities) {

         AppUser ldapUser = appUserRepository.findByLoginId(username);
         if (Objects.isNull(ldapUser)) {
            ldapUser = new AppUser();
            ldapUser.setLoginId(username);
            setLdapAttributes(ldapUser, ctx);
            setLdapTemplateId(ldapUser, ctx);
            appUserRepository.save(ldapUser);
         }
         return new AppUserPrincipal(ldapUser);
      }


      public Map<String, UUID> getLdapCustomTemplates() {
         return ldapProperties.templateId;
      }
      public String getLdapMappingBy() {
         return ldapProperties.mappingBy;
      }
      public Map<String, String> getLdapAttributeNames() {
         return ldapProperties.ldapAttributeNames;
      }

      private void setLdapTemplateId(AppUser ldapUser, DirContextOperations ctx) {
         Map<String, UUID> customTemplates = getLdapCustomTemplates();

         String mappingBy = getLdapMappingBy();
         String attributeValue = getLdapAttribute(mappingBy, ctx);

         if (StringUtils.isNotEmpty(attributeValue) && (Objects.nonNull(customTemplates))) {
            customTemplates.keySet().forEach(key -> {
               if (attributeValue.toLowerCase().contains(key.toLowerCase())) {
                  UUID templateId = customTemplates.get(key);
                  if (Objects.nonNull(templateId)) {
                     ldapUser.setTemplateIds(Collections.singletonList(templateId));
                  }
               }
            });
         }
         if (CollectionUtils.isEmpty(ldapUser.getTemplateIds()) && (Objects.nonNull(customTemplates.get(DEFAULT_TEMPLATE_ID)))) {
            ldapUser.setTemplateIds(Collections.singletonList(customTemplates.get(DEFAULT_TEMPLATE_ID)));
         }
      }

      private void setLdapAttributes(AppUser ldapUser, DirContextOperations ctx) {
         Map<String, String> ldapAttributeNames = getLdapAttributeNames();
         if (Objects.nonNull(ldapAttributeNames)) {
            String keyFirstName = ldapAttributeNames.get(FIRST_NAME),
                  keyLastName = ldapAttributeNames.get(LAST_NAME),
                  keyEmail = ldapAttributeNames.get(EMAIL);

            ldapUser.setFirstName(getLdapAttribute(keyFirstName, ctx));
            ldapUser.setLastName(getLdapAttribute(keyLastName, ctx));
            ldapUser.setEmail(getLdapAttribute(keyEmail, ctx));
         }
      }

      private String getLdapAttribute(String keyName, DirContextOperations ctx) {
         if (StringUtils.isNotEmpty(keyName) && Objects.nonNull(ctx.getStringAttributes(keyName)) && ctx.getStringAttributes(keyName).length > 0) {
            return Arrays.toString(ctx.getStringAttributes(keyName)).substring(1).replaceFirst("]", "");
         }
         return "";
      }
   }

   @Configuration
   @ConfigurationProperties(prefix = "application.ldap")
   @Data
   static class LdapProperties {
      private String userSearchFilter;
      private String userSearchBase;
      private String groupSearchFilter;
      private String groupSearchBase;
      private String url;
      private String managerDn;
      private String managerPassword;
      private Map<String, UUID> templateId;
      private Map<String, String> ldapAttributeNames;
      private String mappingBy = "memberOf";
   }
}
