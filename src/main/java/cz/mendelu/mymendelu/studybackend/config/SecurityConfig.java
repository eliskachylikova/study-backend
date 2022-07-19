package cz.mendelu.mymendelu.studybackend.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakSecurityComponents;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.client.KeycloakClientRequestFactory;
import org.keycloak.adapters.springsecurity.client.KeycloakRestTemplate;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.web.authentication.session.NullAuthenticatedSessionStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

@Configuration
@EnableWebSecurity
@ComponentScan(basePackageClasses = KeycloakSecurityComponents.class)
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter
{

    @Autowired
    private Environment env;

    @Autowired
    public KeycloakClientRequestFactory keycloakClientRequestFactory;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        super.configure(http);

        http
                // General security config
                .cors().and() // enable cors config
                .httpBasic().disable() // we do not need http basic, we are using token authentication instead
                .csrf().disable() // we do not need csrf protection because we have tokens
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // we do not need sessions because we have tokens
                .and()
                .authorizeRequests()


                // Swagger UI
                .antMatchers("/v2/api-docs", "/swagger-ui/**", "/webjars/**", "/swagger-resources/**", "/configuration/security", "/configuration/ui").permitAll() // swagger api docs


                // ### GENERAL ENDPOINTS ###

                // Home
                .antMatchers("/echo").permitAll()

                // Web Sockets
                // We can permit everyone here as specific access rules are defined for specific STOMP destinations in WebSocketSecurityConfig.
                .antMatchers("/socket/**").permitAll()

                // User
                .antMatchers(HttpMethod.GET, "/user").authenticated()


                // ### DOMAIN ENDPOINTS ###

                // --- TEST ENDPOINT ---
                .antMatchers(HttpMethod.GET, "/test/**").authenticated()

                // --- STUDY DEPARTMENT ---

                //isic/login - not used for now
//                .antMatchers(HttpMethod.GET, "/isic/login/**").permitAll()
//                .antMatchers(HttpMethod.POST, "/isic/login/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
//                .antMatchers(HttpMethod.PUT, "/isic/login/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
//                .antMatchers(HttpMethod.DELETE, "/isic/login/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //queue/demand/status
                .antMatchers(HttpMethod.GET, "/queue/demand/status/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.POST, "/queue/demand/status/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/queue/demand/status/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/queue/demand/status/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //queue/demand
                .antMatchers(HttpMethod.GET, "/queue/demand/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.POST, "/queue/demand/**").authenticated()
                .antMatchers(HttpMethod.PUT, "/queue/demand/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/queue/demand/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //study_department/assistant/closed_hours
                .antMatchers(HttpMethod.GET, "/study_department/assistant/closed_hours/**").permitAll()
                .antMatchers(HttpMethod.POST, "/study_department/assistant/closed_hours/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/study_department/assistant/closed_hours/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/study_department/assistant/closed_hours/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //study_department/assistant/changed_queue_items
                .antMatchers(HttpMethod.GET, "/study_department/assistant/changed_queue_items/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //study_department/assistant
                .antMatchers(HttpMethod.GET, "/study_department/assistant/basic").permitAll()
                .antMatchers(HttpMethod.GET, "/study_department/assistant/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.POST, "/study_department/assistant/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/study_department/assistant/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/study_department/assistant/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //study_department/study_fields
                .antMatchers(HttpMethod.GET, "/study_department/study_fields/**").permitAll()
                .antMatchers(HttpMethod.POST, "/study_department/study_fields/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/study_department/study_fields/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/study_department/study_fields/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")

                //study_department/study_problems_category
                .antMatchers(HttpMethod.GET, "/study_department/study_problems_category/**").permitAll()
                .antMatchers(HttpMethod.POST, "/study_department/study_problems_category/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/study_department/study_problems_category/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/study_department/study_problems_category/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")

                //study_department/study_problems_item
                .antMatchers(HttpMethod.GET, "/study_department/study_problems_item/**").permitAll()
                .antMatchers(HttpMethod.POST, "/study_department/study_problems_item/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/study_department/study_problems_item/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/study_department/study_problems_item/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")

                //study_department/open_hours
                .antMatchers(HttpMethod.GET, "/study_department/open_hours/**").permitAll()
                .antMatchers(HttpMethod.POST, "/study_department/open_hours/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.PUT, "/study_department/open_hours/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")
                .antMatchers(HttpMethod.DELETE, "/study_department/open_hours/**").hasAnyRole("STUDY", "STUDY_ADMIN", "STUDY_SPY")

                //study_department/mobile
                .antMatchers(HttpMethod.GET, "/study_department/mobile/**").authenticated()
                .antMatchers(HttpMethod.POST, "/study_department/mobile/**").authenticated()
                .antMatchers(HttpMethod.PUT, "/study_department/mobile/**").authenticated()
                .antMatchers(HttpMethod.DELETE, "/study_department/mobile/**").authenticated()

                //study_department/images
                .antMatchers(HttpMethod.GET, "/study_department/images/**").permitAll()

                //study_department/statistics
                .antMatchers(HttpMethod.GET, "/study_department/statistics/**").hasAnyRole("STUDY_ADMIN", "STUDY_SPY")

                // --- end of STUDY DEPARTMENT ---

                // block everything else not explicitly allowed above
                .anyRequest().denyAll()

                /*.and()
                // convert filter exceptions to JSON
                .addFilterBefore(new ExceptionHandlerFilter(), ChannelProcessingFilter.class)*/
        ;
    }

    /**
     * Registers the KeycloakAuthenticationProvider with the authentication manager.
     */
    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(new SimpleAuthorityMapper());
        auth.authenticationProvider(keycloakAuthenticationProvider);
    }

    @Bean
    @Scope(ConfigurableBeanFactory.SCOPE_PROTOTYPE)
    public KeycloakRestTemplate keycloakRestTemplate() {
        return new KeycloakRestTemplate(keycloakClientRequestFactory);
    }

    /**
     * Defines the session authentication strategy.
     */
    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new NullAuthenticatedSessionStrategy();// use bearer tokens instead of sessions
    }

    @Bean
    public KeycloakConfigResolver KeycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(getAllowedOrigins());
        configuration.setAllowedMethods(List.of("*"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    List<String> getAllowedOrigins(){
        List<String> originsAllowed = List.of("*");

        if (env.getProperty("spring.profiles.active") != null && Objects.equals(env.getProperty("spring.profiles.active"), "prod")) {
            originsAllowed = Arrays.asList(Objects.requireNonNull(env.getProperty("CORS_ALLOWED_ORIGINS")).replaceAll("\\s+","").split(","));
        }
        return originsAllowed;
    }


}
