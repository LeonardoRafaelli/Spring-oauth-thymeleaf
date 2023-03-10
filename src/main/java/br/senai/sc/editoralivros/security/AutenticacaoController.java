package br.senai.sc.editoralivros.security;

import br.senai.sc.editoralivros.model.entity.Pessoa;
import br.senai.sc.editoralivros.security.service.JpaService;
import br.senai.sc.editoralivros.security.users.UserJpa;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@RestController
@RequestMapping("/login")
public class AutenticacaoController {

    private TokenUtils tokenUtils = new TokenUtils();

    @Autowired
    private JpaService jpaService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/auth")
    public ResponseEntity<Object> autenticacao(
            @RequestBody @Valid UsuarioDTO usuarioDTO,
            HttpServletResponse response,
            @CookieValue(name = "jwt", required = false) String jwt
    ) {

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(usuarioDTO.getEmail(),usuarioDTO.getSenha());

        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        System.out.println(authentication.isAuthenticated());

        System.out.println("Cookie: " + jwt);

        if (authentication.isAuthenticated()) {
            String token = tokenUtils.gerarToken(authentication);

            Cookie cookie = new Cookie("jwt", token);
            response.addCookie(cookie);

            UserJpa userJpa = (UserJpa) authentication.getPrincipal();
            Pessoa pessoa = userJpa.getPessoa();

            return ResponseEntity.status(HttpStatus.OK).body(pessoa);
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }



}
