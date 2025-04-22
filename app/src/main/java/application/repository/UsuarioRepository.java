package application.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import application.model.Usuario;

public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    public Usuario findByNomeDeUsuario(String nomeDeUsuario);
}