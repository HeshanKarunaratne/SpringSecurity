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

Granted Authorities are more Granular than Roles (check below snippet to get an idea on authorities and how it has restricted access to different apis and users)

** When adding both roles and authorities to a user authorities only picks up, therefore need to add the role name to authority list with "ROLE_" prefix **

~~~java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    auth
            .inMemoryAuthentication()
            .withUser("admin")
            .password(passwordEncoder().encode("admin123"))
            .authorities("ACCESS_TEST1", "ACCESS_TEST2", "ROLE_ADMIN")
            .and()
            .withUser("heshan")
            .password(passwordEncoder().encode("heshan123"))
            .roles("USER")
            .and()
            .withUser("manager")
            .password(passwordEncoder().encode("manager123"))
            .authorities("ACCESS_TEST1", "ROLE_MANAGER");

}

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .antMatchers("/index.html").permitAll()
            .antMatchers("/profile/**").authenticated()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
            .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
            .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
            .and()
            .httpBasic();
}
~~~

How to Add SSL/HTTPS to Springboot application
 - Certificate
   * Self Signed
   * Buy
 - Modify application.properties
 - Add @Bean of ServletWebServerFactory

1) Navigate to jdk installed location using command prompt using Administrative Mode
  eg: C:\Program Files\Java\jdk-11.0.12\bin>

2) Enter below command
  .\keytool.exe -genkey -alias bootsecurity -storetype PKCS12 -keyalg RSA -keysize 2048 -keystore bootsecurity.p12 -validity 3650

3) Enter details when prompted

4) Copy generated file to Project resources

5) Add below properties to application.properties

~~~java
  server.port=8443
  server.ssl.enabled=true
  server.ssl.key-store=src/main/resources/bootsecurity.p12
  server.ssl.key-store-password=bootsecurity
  server.ssl.key-store-type=PKCS12
  server.ssl.key-alias=bootsecurity
~~~

6) Add below snippets.

~~~java
@Bean
public ServletWebServerFactory servletContainer(){
    TomcatServletWebServerFactory tomcat = new TomcatServletWebServerFactory(){
        @Override
        protected void postProcessContext(Context context) {
            SecurityConstraint securityConstraint = new SecurityConstraint();
            securityConstraint.setUserConstraint("CONFIDENTIAL");
            SecurityCollection collection = new SecurityCollection();
            collection.addPattern("/*");
            securityConstraint.addCollection(collection);
            context.addConstraint(securityConstraint);
        }
    };
  tomcat.addAdditionalTomcatConnectors(httpToHttpsRedirectConnector());
  return tomcat;
}

private Connector httpToHttpsRedirectConnector(){
    Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
    connector.setScheme("http");
    connector.setPort(8080);
    connector.setSecure(false);
    connector.setRedirectPort(8443);
    return connector;
}
~~~

Adding a Database connection to store user Information
    - Create a User entity to store information
    - Store the User in the database
    - Link our User entity with build in classes in Spring Security
        * Link User with UserDetails interface
        * Link UserRepository with UserDetailsService interface
    - Intergrate Database Auth in our configuration


User -> UserPrincipal implements UserDetails
UserRepository -> UserPrincipalDetailsService implements UserDetailsService

Below snippet shows how to map User to UserPrincipal

~~~java
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Heshan Karunaratne
 */
public class UserPrincipal implements UserDetails {

    private final User user;

    @Autowired
    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        this.user.getPermissionList().forEach(
                permissionName -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority(permissionName);
                    authorities.add(authority);
                }
        );

        this.user.getRoleList().forEach(
                roleName -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + roleName);
                    authorities.add(authority);
                }
        );

        return authorities;
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.user.getActive() == 1;
    }
}

~~~

Below snippet shows how to map User to UserPrincipalDetailsService

~~~java

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import rc.bootsecurity.domain.User;
import rc.bootsecurity.domain.UserPrincipal;
import rc.bootsecurity.repository.UserRepository;

/**
 * @author Heshan Karunaratne
 */
@Service
public class UserPrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserPrincipalDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        return new UserPrincipal(user);
    }
}

~~~

Below snippet for User domain 

~~~java

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Heshan Karunaratne
 */
public class UserPrincipal implements UserDetails {

    private final User user;

    @Autowired
    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();

        this.user.getPermissionList().forEach(
                permissionName -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority(permissionName);
                    authorities.add(authority);
                }
        );

        this.user.getRoleList().forEach(
                roleName -> {
                    GrantedAuthority authority = new SimpleGrantedAuthority("ROLE_" + roleName);
                    authorities.add(authority);
                }
        );

        return authorities;
    }

    @Override
    public String getPassword() {
        return this.user.getPassword();
    }

    @Override
    public String getUsername() {
        return this.user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.user.getActive() == 1;
    }
}

~~~

Below snippet after changing from in memory authentication to database authentication

~~~java

import heshan.springsecurity.service.UserPrincipalDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author Heshan Karunaratne
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final UserPrincipalDetailsService userPrincipalDetailsService;

    @Autowired
    public SecurityConfiguration(UserPrincipalDetailsService userPrincipalDetailsService) {
        this.userPrincipalDetailsService = userPrincipalDetailsService;
    }

 
    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(authenticationProvider());
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/**").authenticated()
                .antMatchers("/admin/**").hasRole("ADMIN")
                .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                .antMatchers("/api/public/users").hasRole("ADMIN")
                .and()
                .httpBasic();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(this.userPrincipalDetailsService);
        return daoAuthenticationProvider;
    }
}

~~~

Forms Authentication: Add a custom login page to authenticate the users.
Create your custom login view and controller.
(Even though you have implemented a get /login endpoint you didnt wanted to create a post /login endpoint - Spring Security handled it for us)

~~~java

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .antMatchers("/index.html").permitAll()
            .antMatchers("/profile/**").authenticated()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
            .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
            .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
            .antMatchers("/api/public/users").hasRole("ADMIN")
            .and()
            .formLogin()
            .loginPage("/login")
            .permitAll();
}
~~~

With Form authentication need to create a /logout endpoint for the logged in users to log out.
Following changes can enable logout and remember me screens from Spring Security out of the box. 
Below list is the default values for form based Authentication

login endpoint -> /login
username id, name -> username
password id, name -> password
remember me id, name -> remember-me

~~~java

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .antMatchers("/index.html").permitAll()
            .antMatchers("/profile/**").authenticated()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
            .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
            .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
            .antMatchers("/api/public/users").hasRole("ADMIN")
            .and()

            .formLogin()
            .loginPage("/login")
            .permitAll()
            .and()

            .logout()
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/login")

            .and()
            .rememberMe()
            .tokenValiditySeconds(3600);
}

~~~

When you changed defaults value for login endpoint, username, password and remember me we need to tell Spring Security to adjust to new values like below

~~~java

@Override
protected void configure(HttpSecurity http) throws Exception {
    http
            .authorizeRequests()
            .antMatchers("/index.html").permitAll()
            .antMatchers("/profile/**").authenticated()
            .antMatchers("/admin/**").hasRole("ADMIN")
            .antMatchers("/management/**").hasAnyRole("ADMIN", "MANAGER")
            .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
            .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
            .antMatchers("/api/public/users").hasRole("ADMIN")
            .and()

            .formLogin()
            .loginProcessingUrl("/signin")
            .loginPage("/login")
            .permitAll()
            .usernameParameter("txtUsername")
            .passwordParameter("txtPassword")
            .and()

            .logout()
            .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
            .logoutSuccessUrl("/login")

            .and()
            .rememberMe()
            .tokenValiditySeconds(3600)
            .key("mySecret!")
            .rememberMeParameter("checkRememberMe");

}

~~~

View Updates based on security
 - Show / hide content based on user is authenticated or not
 - Show / hide content based on user has different roles and permission


Add below dependency
<dependency>
    <groupId>org.thymeleaf.extras</groupId>
    <artifactId>thymeleaf-extras-springsecurity5</artifactId>
</dependency>


JWT Section