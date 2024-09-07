package bj.nazonhou.springsecuritydemystified;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Map;

public class ServerAuthenticationProvider implements org.springframework.security.authentication.AuthenticationProvider {
    private final Map<String, String> servers = Map.of(
            "98Y59834", "WebServer01 🖥️",
            "89U454F9", "DNS 🛜"
    );

    /**
     * Performs authentication with the same contract as
     * {@link AuthenticationManager#authenticate(Authentication)}
     * .
     *
     * @param authentication the authentication request object.
     * @return a fully authenticated object including credentials. May return
     * <code>null</code> if the <code>AuthenticationProvider</code> is unable to support
     * authentication of the passed <code>Authentication</code> object. In such a case,
     * the next <code>AuthenticationProvider</code> that supports the presented
     * <code>Authentication</code> class will be tried.
     * @throws AuthenticationException if authentication fails.
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        ServerAuthentication serverAuthentication = (ServerAuthentication) authentication;
        if (!servers.containsKey(serverAuthentication.getCredentials())) {
            throw new BadCredentialsException("You're not a valid server 🤗⛔");
        }

        return serverAuthentication
                .setPrincipal(servers.get(serverAuthentication.getCredentials()))
                .setName(serverAuthentication.getCredentials().toString())
                .setAuthorities(AuthorityUtils.createAuthorityList("can-access-private"))
                .authenticate()
                .setCredentials(null);
    }

    /**
     * Returns <code>true</code> if this <Code>AuthenticationProvider</code> supports the
     * indicated <Code>Authentication</code> object.
     * <p>
     * Returning <code>true</code> does not guarantee an
     * <code>AuthenticationProvider</code> will be able to authenticate the presented
     * <code>Authentication</code> object. It simply indicates it can support closer
     * evaluation of it. An <code>AuthenticationProvider</code> can still return
     * <code>null</code> from the {@link #authenticate(Authentication)} method to indicate
     * another <code>AuthenticationProvider</code> should be tried.
     * </p>
     * <p>
     * Selection of an <code>AuthenticationProvider</code> capable of performing
     * authentication is conducted at runtime the <code>ProviderManager</code>.
     * </p>
     *
     * @param authentication
     * @return <code>true</code> if the implementation can more closely evaluate the
     * <code>Authentication</code> class presented
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return ServerAuthentication.class.isAssignableFrom(authentication);
    }
}
