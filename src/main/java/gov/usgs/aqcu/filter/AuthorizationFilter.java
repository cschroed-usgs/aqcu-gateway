package gov.usgs.aqcu.filter;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;
import org.springframework.cloud.netflix.zuul.filters.support.FilterConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;

@Component
public class AuthorizationFilter extends ZuulFilter {

    private final AntPathMatcher pathMatcher;

    @Autowired
    public AuthorizationFilter(AntPathMatcher pathMatcher) {
        this.pathMatcher = pathMatcher;
    }

    @Override
    public boolean shouldFilter() {
        return true;
    }

    @Override
    public Object run() throws ZuulException {
        final RequestContext requestContext = RequestContext.getCurrentContext();
        String requestURI = requestContext.getRequest().getRequestURI();
        OAuth2Authentication auth = (OAuth2Authentication) SecurityContextHolder.getContext().getAuthentication();

        if (claimNode.isPresent()) {
            String userRoleInToken = requestContext.get("userRole").toString();
            validateUserRoleClaim(userRoleInToken, claimNode.get());
            validateUrlClaim(requestURI, claimNode.get().getUrlClaimPattern(), requestContext);
            addClaimsToRequestAsHeaders(requestContext);
        } else {
            throw new ZuulException("Invalid Token", HttpStatus.FORBIDDEN.value(), "Invalid Route");
        }
        requestContext.put(IS_SESSION_UPDATE_REQUIRED, true);
        return null;
    }

    public run() {

    }

    /**
     * Searches case-sensitively for `authority` in a user's `authentication`.
     *
     * The case-sensitivity protects against internal security threats. If it
     * were case-insensitive then a malicious AD/LDAP admin could create a group
     * with the same name, but different case, add themselves to the
     * differently-cased group, and thus gain unauthorized access.
     *
     * @param authentication
     * @param authority
     * @return true if `authority` is in a user's `authentication`. false
     * otherwise.
     */
    protected boolean hasAuthority(Authentication authentication, String authority) {
        boolean hasAuthority = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .map(this::removeRolePrefix)
                .anyMatch((a) -> a.equals(authority));
        return hasAuthority;
    }

    	/**
	 * 
	 * @param authority
	 * @return 
	 */
	protected String removeRolePrefix(String authority) {
		if (authority.startsWith(ROLE_PREFIX)) {
			return authority.substring(ROLE_PREFIX.length());
		} else {
			return authority;
		}
	}
    
    @Override
    public String filterType() {
        return FilterConstants.PRE_TYPE;
    }

    @Override
    public int filterOrder() {
        return FilterConstants.PRE_DECORATION_FILTER_ORDER - 2;
    }

}
