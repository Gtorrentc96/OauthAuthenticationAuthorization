# Ouath2 Authentication & Authorization Flow

In this example Oauth2 is used to both authenticate and authorize the owner.
In this case the client doesn't need to store the user's (owner) login and password since
the authentication is done though the resource server (GitHub in our case). The authorization is 
done as in the other example: https://github.com/DSI-Tecnocampus/GitHubOauth

The authentication is accomplished using a security filter that is added at the begining
of the filters chain so that the login is performed though the Oauth2 protocol.