package bj.nazonhou.springsecuritydemystified;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.Collection;
import java.util.Collections;

public class ServerAuthentication implements Authentication {
    private Collection<? extends GrantedAuthority> authorities = AuthorityUtils.createAuthorityList(Collections.emptyList());
    private String credentials;
    private String principal;
    private String name;
    private boolean isAuthenticated = false;

    public ServerAuthentication(Boolean authenticated, String credentials) {
        setAuthenticated(authenticated);
        setCredentials(credentials);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public ServerAuthentication setAuthorities(Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        return this;
    }

    @Override
    public Object getCredentials() {
        return this.credentials;
    }

    public ServerAuthentication setCredentials(String credentials) {
        this.credentials = credentials;
        return this;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public ServerAuthentication setPrincipal(String principal) {
        this.principal = principal;
        return this;
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    /**
     * See {@link #isAuthenticated()} for a full description.
     * <p>
     * Implementations should <b>always</b> allow this method to be called with a
     * <code>false</code> parameter, as this is used by various classes to specify the
     * authentication token should not be trusted. If an implementation wishes to reject
     * an invocation with a <code>true</code> parameter (which would indicate the
     * authentication token is trusted - a potential security risk) the implementation
     * should throw an {@link IllegalArgumentException}.
     *
     * @param isAuthenticated <code>true</code> if the token should be trusted (which may
     *                        result in an exception) or <code>false</code> if the token should not be trusted
     * @throws IllegalArgumentException if an attempt to make the authentication token
     *                                  trusted (by passing <code>true</code> as the argument) is rejected due to the
     *                                  implementation being immutable or implementing its own alternative approach to
     *                                  {@link #isAuthenticated()}
     */
    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    public ServerAuthentication authenticate() {
        setAuthenticated(true);
        return this;
    }

    /**
     * Returns the name of this {@code Principal}.
     *
     * @return the name of this {@code Principal}.
     */
    @Override
    public String getName() {
        return name;
    }

    public ServerAuthentication setName(String name) {
        this.name = name;
        return this;
    }
}
