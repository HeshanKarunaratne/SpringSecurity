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

~~~java
@Override
protected void configure(AuthenticationManagerBuilder auth) throws Exception {

    auth
            .inMemoryAuthentication()
            .withUser("admin")
            .password(passwordEncoder().encode("admin123"))
            .roles("ADMIN")
            .authorities("ACCESS_TEST1", "ACCESS_TEST2")
            .and()
            .withUser("heshan")
            .password(passwordEncoder().encode("heshan123"))
            .roles("USER")
            .and()
            .withUser("manager")
            .password(passwordEncoder().encode("manager123"))
            .roles("MANAGER")
            .authorities("ACCESS_TEST1");

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
