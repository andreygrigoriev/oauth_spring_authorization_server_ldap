package com.netcracker.oauth_spring_authorization_server_ldap.repository;

import com.netcracker.oauth_spring_authorization_server_ldap.model.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface AppUserRepository extends JpaRepository<AppUser, UUID> {
   AppUser findByLoginId(String loginId);
}
