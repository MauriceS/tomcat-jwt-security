package it.cosenonjaviste.security.jwt.valves;

import com.auth0.jwk.*;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import it.cosenonjaviste.security.jwt.model.JwtAdapter;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Optional;

/**
 * OpenId Connect idToken validation based on JWKS uri with fallback to basic authentication
 *
 * @author maurice
 */
public class OidcJwtTokenWithFallbackValve extends OidcJwtTokenValve {

    private static final Log LOG = LogFactory.getLog(OidcJwtTokenWithFallbackValve.class);

    public OidcJwtTokenWithFallbackValve() {
        super.defaults();
    }

    @Override
    protected void handleAuthentication(Request request, Response response) throws IOException, ServletException {
        try {
            String authorizationHeader = request.getHeader("Authorization");
            Optional<DecodedJWT> optionalJwt = super.getJwtFrom(authorizationHeader);
            if (optionalJwt.isPresent()) {
                JwtAdapter jwtAdapter = super.verify(optionalJwt.get());
                authenticateRequest(request, jwtAdapter);
                this.getNext().invoke(request, response);
            } else {
                if (hasBasicAuth(authorizationHeader)) {
                  this.getNext().invoke(request, response);
                } else {
                  sendUnauthorizedError(request, response, "Authorization token not provided");
                }
            }
        } catch (JwkException e) {
            LOG.error(e.getMessage(), e);
            sendUnauthorizedError(request, response, e.getMessage());
        } catch (JWTVerificationException e) {
            sendUnauthorizedError(request, response, e.getMessage());
        }
    }

    private boolean hasBasicAuth(String authHeader) {
      return authHeader != null && authHeader.toLowerCase().startsWith("basic");
    }
}
