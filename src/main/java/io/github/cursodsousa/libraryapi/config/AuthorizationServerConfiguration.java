package io.github.cursodsousa.libraryapi.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfiguration {

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // Habilitar autorization server com apply

        //Isso aqui faz MUITA coisa automaticamente:
        //
        //Cria endpoints:
        //
        ///oauth2/token
        //
        ///oauth2/authorize
        //
        ///.well-known/openid-configuration
        //
        ///.well-known/jwks.json
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

        //Pega o configurar
        //Aqui você diz:
        //
        //“Além de OAuth2, eu quero OIDC”
        //
        //Isso adiciona:
        //
        ///userinfo
        //
        //id_token
        //
        //identidade do usuário no JWT
        //
        //📌 OAuth2 → autorização
        //📌 OIDC → identidade (quem é o usuário)
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                //pegar as informações de quem conectou
                .oidc(Customizer.withDefaults());

        //Ira utilizar jwt
        //Essa parte confunde muita gente, mas você acertou.
        //
        //👉 Esse Authorization Server também precisa agir como Resource Server, porque:
        //
        ///userinfo
        //
        //endpoints OIDC
        //
        //endpoints protegidos internos
        //
        //Eles recebem JWT, então precisam validar.
        //
        //📌 Isso NÃO transforma sua API de negócio em Resource Server
        //📌 Só permite que o próprio Auth Server valide tokens
        http.oauth2ResourceServer(oauth2Rs -> oauth2Rs.jwt(Customizer.withDefaults()));

        http.formLogin(configurer -> configurer.loginPage("/login"));

       return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                //access_token: utilizado nas requisições
                .accessTokenTimeToLive(Duration.ofMinutes(60))
                //refresh token servindo para renovar o access_token
                .refreshTokenTimeToLive(Duration.ofMinutes(90))
                .build();
    }

    @Bean
    public ClientSettings clientSettings() {
        return ClientSettings.builder()
                .requireAuthorizationConsent(false)
                .build();
    }
    //GERA JWK - JSON Web Key - serve para assinar o jwt
    @Bean
    public JWKSource<SecurityContext> jwkSource() throws Exception {
        RSAKey rsaKey = gerarChaveRSA();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }



    //GERAR PAR DE CHAVES RSA
    private RSAKey gerarChaveRSA() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey chavePublica = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey chavePrivada = (RSAPrivateKey) keyPair.getPrivate();

        return new RSAKey
                .Builder(chavePublica)
                .privateKey(chavePrivada)
                .keyID(UUID.randomUUID().toString())
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {

        return AuthorizationServerSettings
                .builder()

                // Endpoint onde o CLIENT solicita tokens ao Authorization Server
                // Usado nos fluxos:
                // - Authorization Code
                // - Client Credentials
                // - Refresh Token
                // Retorna access_token, refresh_token, expires_in, etc.
                .tokenEndpoint("/oauth2/token")

                // Endpoint usado por Resource Servers para VALIDAR um token
                // Serve para consultar:
                // - se o token está ativo
                // - escopos
                // - data de expiração
                // Muito usado quando NÃO se trabalha apenas com JWT local
                .tokenIntrospectionEndpoint("/oauth2/introspect")

                // Endpoint que permite REVOGAR tokens
                // Pode invalidar:
                // - access_token
                // - refresh_token
                // Importante para logout, segurança e revogação manual
                .tokenRevocationEndpoint("/oauth2/revoke")

                // Endpoint inicial do fluxo Authorization Code
                // É aqui que o USUÁRIO é redirecionado para autenticação
                // Após login e consentimento, retorna o authorization code
                .authorizationEndpoint("/oauth2/authorize")

                // Endpoint do OpenID Connect (OIDC)
                // Retorna informações do usuário autenticado (claims)
                // Ex: sub, email, nome
                .oidcUserInfoEndpoint("/oauth2/userinfo")

                // Endpoint que expõe as chaves públicas (JWK)
                // Usado por Resource Servers para validar JWT
                // Fundamental quando se trabalha com JWT + RSA
                .jwkSetEndpoint("/oauth2/jwks")

                // Endpoint de logout do OpenID Connect
                // Finaliza a sessão do usuário no Authorization Server
                // Usado em logout centralizado (Single Logout)
                .oidcLogoutEndpoint("/oauth2/logout")

                .build();
    }


}
