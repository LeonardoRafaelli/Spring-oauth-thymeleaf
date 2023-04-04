package br.senai.sc.editoralivros.security;

import br.senai.sc.editoralivros.security.service.GoogleService;
import br.senai.sc.editoralivros.security.service.JpaService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@AllArgsConstructor
public class AutenticacaoConfig {
    // No browser, ao acessar a rota irá pedir login e senha:
    // - usuário: user
    // - senha: a que gerar quando rodar
    private JpaService jpaService;
    private GoogleService googleService;

    @Autowired
    public void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .userDetailsService(jpaService)
                .passwordEncoder(NoOpPasswordEncoder.getInstance());
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();

        corsConfiguration.setAllowedOrigins(List.of(
                "http://localhost:3000"
        ));

        corsConfiguration.setAllowedMethods(List.of(
                "POST", "DELETE", "PUT", "GET"
        ));

        // Para conseguir gravar e recuperar um cookie do navegador
        corsConfiguration.setAllowCredentials(true);

        corsConfiguration.setAllowedHeaders(List.of("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfiguration);

        return source;
    }

    // Configura as autorizações de acesso
    @Bean
    protected SecurityFilterChain configure(HttpSecurity httpSecurity) {

        try {
            httpSecurity.authorizeHttpRequests()
                    // Para a rota de login, estamos liberando o método post a todos
                    .antMatchers("/editoralivros/login",
                            "/editoralivros/usuarios",
                            "/editoralivros/pessoa",
                            "/login",
                            "/login/auth",
                            "/v3/api-docs/**",
                            "/swagger-ui.html",
                            "/swagger-ui/**").permitAll()
                    .antMatchers(HttpMethod.POST, "/editoralivros/livro").hasAuthority("Autor")
                    // Determina que todas as demais requisições terão de ser autenticadas
                    .anyRequest().authenticated();
            httpSecurity
                    .csrf().disable();
            httpSecurity
                    .cors()
                    .configurationSource(
                            corsConfigurationSource());

            httpSecurity
                    .logout().permitAll();

            // Autentica mas não deixa a sessão do usuário ativa (pq o objetivo é usar o token para validação de autorização)
            httpSecurity.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

            // Faz com que antes de qualquer requisição é necessário passar pelo filtro
            httpSecurity.addFilterBefore(new AutenticacaoFiltro(new TokenUtils(), jpaService), UsernamePasswordAuthenticationFilter.class);

            return httpSecurity.build();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // Serve para poder fazer a injeção de dependência dentro da autenticação controller, em suma, para poder usar o @Autowired
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration ac) throws Exception {
        return ac.getAuthenticationManager();
    }

    public static void main(String[] args) {
        System.out.println(new BCryptPasswordEncoder().encode("123"));
    }
}