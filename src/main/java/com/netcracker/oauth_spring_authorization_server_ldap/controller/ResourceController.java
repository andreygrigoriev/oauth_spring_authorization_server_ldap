package com.netcracker.oauth_spring_authorization_server_ldap.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {
   @GetMapping("/rest/test1")
   public String test1() {
      return "test1";
   }

   @GetMapping("/rest/test2")
   public String test2() {
      return "test2";
   }
}
