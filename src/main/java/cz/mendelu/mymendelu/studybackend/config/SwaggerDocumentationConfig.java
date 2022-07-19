package cz.mendelu.mymendelu.studybackend.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.SecurityConfiguration;
import springfox.documentation.swagger.web.SecurityConfigurationBuilder;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SwaggerDocumentationConfig {

    private static final String PATH = "/.*";

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${swagger.auth.token-url:}")
    private String authTokenUrl;

    @Value("${swagger.auth.client-id:}")
    private String authClientId;

    @Bean
    public Docket api() {
        return new Docket(DocumentationType.SWAGGER_2)
                .ignoredParameterTypes(AuthenticationPrincipal.class)
                .apiInfo(apiInfo())
                .select()
                .paths(PathSelectors.regex(PATH))
                .build()
                .securityContexts(List.of(securityContext()))
                .securitySchemes(List.of(securitySchema()));
    }

    @Bean
    public SecurityConfiguration securityConfiguration() {
        return SecurityConfigurationBuilder.builder()
                .clientId(authClientId)
                .clientSecret("")
                .realm(realm)
                .appName("")
                .additionalQueryStringParams(null)
                .useBasicAuthenticationWithAccessCodeGrant(false)
                .enableCsrfSupport(false)
                .build();
    }

    private OAuth securitySchema() {
        List<GrantType> grantTypes = List.of(new ResourceOwnerPasswordCredentialsGrant(authTokenUrl));
        //List<GrantType> grantTypes = Lists.newArrayList(new ResourceOwnerPasswordCredentialsGrant(authTokenUrl));
        return new OAuth("oauth2", new ArrayList<>(), grantTypes);
    }

    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(List.of(new SecurityReference("oauth2", new AuthorizationScope[0])))
                .build();
    }

    private ApiInfo apiInfo() {
        String serverVersion = "0.0.1";
        String applicationName = "My MENDELU Study Department";
        return new ApiInfoBuilder()
                .title(applicationName)
                .description("Server documentation.")
                .version(serverVersion)
                .build();
    }

}
