package io.github.cursodsousa.libraryapi.security;

import io.github.cursodsousa.libraryapi.model.Usuario;
import io.github.cursodsousa.libraryapi.service.UsuarioService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

@Component
@RequiredArgsConstructor
public class LoginSocialSuccesHandler extends SavedRequestAwareAuthenticationSuccessHandler  {

    private final UsuarioService usuarioService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws ServletException, IOException {

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) authentication;
        OAuth2User oAuth2User = token.getPrincipal();

        String email = oAuth2User.getAttribute("email");

        Usuario usuarioEncontrado = usuarioService.obterPorEmail(email);

        if(usuarioEncontrado == null) {
            usuarioEncontrado =  criarUsuarioGoogle(email);
        }

        authentication = new CustomAuthentication(usuarioEncontrado);

        System.out.println("ANTES DO setAuthentication");
        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("DEPOIS DO setAuthentication");
        super.onAuthenticationSuccess(request, response, authentication);
        System.out.println("FIM DO onAuthenticationSuccess");
    }

    private Usuario criarUsuarioGoogle(String email) {
        Usuario usuario;
        usuario = new Usuario();
        usuario.setEmail(email);
        usuario.setLogin(email.substring(0, email.indexOf("@")));
        usuario.setSenha("123456");
        usuario.setRoles(List.of("OPERADOR"));

        usuarioService.salvar(usuario);

        return usuario;
    }
}
