package com.leall.medication_reminder.infrastructure.config.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenValidator jwtTokenValidator;

    public JwtAuthenticationFilter(JwtTokenValidator jwtTokenValidator) {
        this.jwtTokenValidator = jwtTokenValidator;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                    FilterChain filterChain) throws ServletException, IOException {
        
        String authHeader = request.getHeader("Authorization");
        
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            
            try {
                // Validar token
                if (!jwtTokenValidator.isTokenExpired(token) && 
                    jwtTokenValidator.isTokenFromCorrectIssuer(token)) {
                    
                    // Extrair informações do usuário
                    String userId = jwtTokenValidator.getUserIdFromToken(token);
                    String username = jwtTokenValidator.getUsernameFromToken(token);
                    List<String> roles = jwtTokenValidator.getRolesFromToken(token);
                    
                    // Converter roles para GrantedAuthority
                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(SimpleGrantedAuthority::new)
                            .collect(Collectors.toList());
                    
                    // Criar autenticação
                    UsernamePasswordAuthenticationToken authentication = 
                            new UsernamePasswordAuthenticationToken(userId, null, authorities);
                    
                    // Adicionar username como detalhe adicional
                    authentication.setDetails(username);
                    
                    // Configurar no contexto de segurança
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception e) {
                // Token inválido - continuar sem autenticação
                logger.warn("Token JWT inválido: " + e.getMessage());
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
