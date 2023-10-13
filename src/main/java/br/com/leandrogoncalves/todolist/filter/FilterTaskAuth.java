package br.com.leandrogoncalves.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.leandrogoncalves.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

    @Autowired
    private IUserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Pegar a autenticação do usuário
            var authorization = request.getHeader("Authorization");

            var separatesBasic = authorization.substring("Basic".length()).trim();

            byte[] authDecoder = Base64.getDecoder().decode(separatesBasic);

            var userDataPass = new String(authDecoder);

            String[] credentials = userDataPass.split(":");

            String username = credentials[0];
            String password = credentials[1];
        // Validar usuário
            var user = this.userRepository.findByUsername(username);

            if(user == null) {
                response.sendError(401, "User not authorized");
                return;
            } else {
                // Validar senha
                var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), user.getPassword());
                if (!passwordVerify.verified) {
                    response.sendError(401, "User not authorized");
                    return;
                } else {
                    filterChain.doFilter(request, response);
                }
                // Segue o fluxo
            }
        
    }

    
}
