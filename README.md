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


To add Security to an unsecure Springboot application add below dependency
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
    <scope>test</scope>
</dependency>

Will be redirected to a basic login page given by Spring Security
default username: user
password: generated password in the console

To Enable HTTP basic Authentication- use below snippet

~~~java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {

        /**
         * In memory authentication
         */
        auth
                .inMemoryAuthentication()
                .withUser("admin").password(passwordEncoder().encode("admin123")).roles("ADMIN")
                .and()
                .withUser("heshan").password(passwordEncoder().encode("123")).roles("USER");

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder(){
         return new BCryptPasswordEncoder();
    }
}
~~~

Below Snippet shows how routes are matched according to ROLES and permission
**** THE ORDER OF antMatchers is a must ***

~~~java
@Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN","MANAGER")
                .and()
                .httpBasic();
    }
~~~