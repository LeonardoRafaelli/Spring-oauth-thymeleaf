package br.senai.sc.editoralivros.security;

import br.senai.sc.editoralivros.security.service.JpaService;
import br.senai.sc.editoralivros.security.users.UserJpa;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@AllArgsConstructor
public class AutenticacaoFiltro extends OncePerRequestFilter {

    private JpaService jpaService;
    private TokenUtils tokenUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = request.getHeader("Authorization");
        if (token != null && token.startsWith("Bearer ")) {
            token = token.substring(7);
        } else {
            token = null;
        }
        Boolean valido = tokenUtils.validarToken(token);
        if (valido) {
            Long usuarioCpf = tokenUtils.getUsuarioCpf(token);
            UserJpa userJpa = (UserJpa) jpaService.loadUserByUsername(usuarioCpf.toString());
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken =
                    new UsernamePasswordAuthenticationToken(userJpa.getUsername(),
                            null, userJpa.getAuthorities());
            //
            SecurityContextHolder.getContext().setAuthentication(
                    usernamePasswordAuthenticationToken
            );
        } else if (!request.getRequestURI().equals("/editora-livros-api/login") ||
                !request.getRequestURI().equals("/editora-livros-api/usuarios")) {
            response.setStatus(401);
        }
        filterChain.doFilter(request, response);
    }
}
