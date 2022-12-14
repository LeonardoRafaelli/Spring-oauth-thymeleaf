package br.senai.sc.editoralivros.security.service;

import br.senai.sc.editoralivros.model.entity.Pessoa;
import br.senai.sc.editoralivros.repository.PessoaRepository;
import br.senai.sc.editoralivros.security.users.UserJpa;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Optional;

@Service
public class JpaService implements UserDetailsService {

    @Autowired
    private PessoaRepository pessoaRepository;

    private final String senhaForte = "c127a7b6adb013a5ff879ae71afa62afa4b4ceb72afaa54711dbcde67b6dc325";

    @Override
    public UserDetails loadUserByUsername(
            String username) throws UsernameNotFoundException {
        Optional<Pessoa> pessoaOptional =
                pessoaRepository.findByEmail(username);
        if (pessoaOptional.isPresent()) {
            return new UserJpa(pessoaOptional.get());
        }
        throw new UsernameNotFoundException("Usuário não encontrado!");
    }

    public String gerarToken(Authentication authentication) {
        Pessoa pessoa = (Pessoa) authentication.getPrincipal();
        return Jwts.builder()
                .setIssuer("Editora de Livros")
                .setSubject(pessoa.getCpf().toString())
                .setIssuedAt(new Date())
                .setExpiration(new Date(new Date().getTime() + 1800000))
                .signWith(SignatureAlgorithm.HS256, senhaForte)
                .compact();
    }

    public Boolean validarToken(String token) {
        try {
            Jwts.parser().setSigningKey(senhaForte).parseClaimsJws(token);
            return true;
        } catch (Exception e) {
            return false;
        }

    }

    public UserJpa getUsuario(String token) {
        Long cpf = Long.parseLong(Jwts.parser()
                .setSigningKey(senhaForte)
                .parseClaimsJws(token)
                .getBody().getSubject());
        return new UserJpa(pessoaRepository.findById(cpf).get());
    }
}
