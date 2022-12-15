# Spring Security

 - Authentication And Authorization
 - HTTP Basic Authentication
 - Forms Authentication
 - Token Based Authentication
 - Authorities And Roles
 - SSL And HTTPS

Keywords in the context of Spring Security
 Authentication: Who is this
 Authorization: What he can do
 Granted Authorities: READ_PROFILE, EDIT_PROFILE (Different actions that can be done)
 Roles: ROLE_ADMIN, ROLE_USER (Should start with 'ROLE' Prefix and this denotes different user groups with different access)
 
JWT - JsonWebToken
  - Header
  - Payload
  - Secret

Form Based Authentication: 
  - Custom HTML page that will collect credentials and take responsibility to collect form data (creates SESSION_ID and returns auth cookie and used this auth cookie when sending api calls)
  - Most suited for self contained apps that do not expose public APIs to other parties
  
HTTP Basic Authentication
  - Browser request a username and a password when making a request in order to authenticate a user
  - username:password
