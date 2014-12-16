import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.ws.Response;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * Created by i843719 on 11/20/14.
 */
@Path("/authz")
public class AuthzEndpoint {
    @Inject
    private Database database;

    @GET
    public Response authorize(@Context HttpServletRequest request)
            throws URISyntaxException, OAuthSystemException {
        try {
            OAuthAuthzRequest oauthRequest =
                    new OAuthAuthzRequest(request);
            OAuthIssuerImpl oauthIssuerImpl =
                    new OAuthIssuerImpl(new MD5Generator());

            //build response according to response_type
            String responseType =
                    oauthRequest.getParam(OAuth.OAUTH_RESPONSE_TYPE);

            OAuthASResponse.OAuthAuthorizationResponseBuilder builder =
                    OAuthASResponse.authorizationResponse(request,
                            HttpServletResponse.SC_FOUND);

            // 1
            if (responseType.equals(ResponseType.CODE.toString())) {
                final String authorizationCode =
                        oauthIssuerImpl.authorizationCode();
                database.addAuthCode(authorizationCode);
                builder.setCode(authorizationCode);
            }

            String redirectURI =
                    oauthRequest.getParam(OAuth.OAUTH_REDIRECT_URI);
            final OAuthResponse response = builder
                    .location(redirectURI)
                    .buildQueryMessage();
            URI url = new URI(response.getLocationUri());
            return Response.status(response.getResponseStatus())
                    .location(url)
                    .build();
        } catch (OAuthProblemException e) {
            // ...
        }
    }
}