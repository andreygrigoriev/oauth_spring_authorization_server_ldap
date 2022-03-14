package com.netcracker.oauth_spring_authorization_server_ldap.model;

import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.Type;

import javax.persistence.*;
import java.io.Serializable;
import java.util.List;
import java.util.UUID;

@Data
@Entity
@Table(name = "app_users")
@NoArgsConstructor
//@JsonIgnoreProperties(ignoreUnknown = true)
public class AppUser implements Serializable {
   private static final long serialVersionUID = -1L;
   @Id
   @GeneratedValue(generator = "UUID")
   @Type(type = "uuid-char")
   private UUID id;
   private String loginId;
   private String password;
   private String status;
   private String firstName;
   private String lastName;
   private String email;
   private Integer age;
   private String companyName;
   @Transient
   private List<UUID> templateIds;
}
