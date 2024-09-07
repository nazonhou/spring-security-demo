package bj.nazonhou.springsecuritydemystified;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class ServerFilter extends OncePerRequestFilter {
    private final AuthenticationManager authenticationManager;

    private final String HEADER_NAME = "x-api-key";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        // Check if this filter can handle the request
        if (request.getHeader(HEADER_NAME) == null) {
            filterChain.doFilter(request, response);
            return;
        }

        // Transform request to authentication request
        ServerAuthentication authenticationRequest = new ServerAuthentication(false,
                request.getHeader(HEADER_NAME));

        // Pass the authenticationRequest to authentication manager
        try {
            Authentication authentication = authenticationManager.authenticate(authenticationRequest);
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(securityContext);
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setCharacterEncoding("utf-8");
            response.setHeader("Content-Type", "text/plain;charset=utf-8");
            response.getWriter().println(e.getMessage());
        }
    }
}
