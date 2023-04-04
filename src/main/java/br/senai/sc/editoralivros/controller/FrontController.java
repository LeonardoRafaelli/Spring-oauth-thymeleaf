package br.senai.sc.editoralivros.controller;

import br.senai.sc.editoralivros.model.entity.Pessoa;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@RestController
@RequestMapping("/editora-livros-api")
@EnableSwagger2
public class FrontController {

        @GetMapping("/login")
        public String login() {
            return "login";
        }

        @GetMapping("/home")
        public String home() {
            return "home";
        }

        @GetMapping("/livros")
        public String livros() {
            return "cadastro-livros";
        }

        @GetMapping("/usuarios")
        public String usuario(Authentication authentication, Model model) {
            Pessoa pessoa = new Pessoa();
            if(authentication != null){
                if(authentication instanceof OAuth2AuthenticationToken){
                    OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
                    pessoa.setNome(oAuth2User.getAttribute("given_name"));
                    pessoa.setSobrenome(oAuth2User.getAttribute("family_name"));
                    pessoa.setEmail(oAuth2User.getAttribute("email"));
                }
//                return "cadastro-usuarios";
            }
            model.addAttribute("pessoa", pessoa);
            return "cadastro-usuarios";
        }
}
