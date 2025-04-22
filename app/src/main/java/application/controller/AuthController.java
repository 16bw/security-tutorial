package application.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import application.model.Usuario;
import application.repository.UsuarioRepository;
import application.service.TokenService;

@RestController
@RequestMapping("/auth")
public class AuthController {
    @Autowired
    private AuthenticationManager authManager;
    
    @Autowired
    private TokenService tokenService;
    
    @Autowired
    private UsuarioRepository usuarioRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    @PostMapping
    public String login(@RequestBody Usuario usuario) {
        UsernamePasswordAuthenticationToken tk = new UsernamePasswordAuthenticationToken(
            usuario.getNomeDeUsuario(), usuario.getSenha());
        authManager.authenticate(tk);
        return tokenService.generateToken(usuario);
    }
    
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Usuario usuario) {
        // Verificar se o usuário já existe
        if (usuarioRepository.findByNomeDeUsuario(usuario.getNomeDeUsuario()) != null) {
            return ResponseEntity.badRequest().body("Nome de usuário já existe");
        }
        
        // Criptografar a senha
        String senhaCriptografada = passwordEncoder.encode(usuario.getSenha());
        usuario.setSenha(senhaCriptografada);
        
        // Salvar o usuário
        usuarioRepository.save(usuario);
        
        // Gerar token para o novo usuário
        String token = tokenService.generateToken(usuario);
        
        return ResponseEntity.ok(token);
    }
}