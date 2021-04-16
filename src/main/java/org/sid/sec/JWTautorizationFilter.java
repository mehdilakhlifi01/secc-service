package org.sid.sec;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JWTautorizationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        response.addHeader("Access-Control-Allow-Origin","*");//je autorise tous les requet qui vient n'importe quelle domaine 
        response.addHeader("Access-Control-Allow-Headers","Origin,Accept,X-Requested-With,Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers,authorization");//je te autorize dans la prochaine requet de m'envoyer les entete suivants
        response.addHeader("Access-Control-Expose-Headers","Access-Control-Allow-Origin, Access-Control-Allow-Credentials, authorization");//angular il'ya le droite de lire les entetes 
        response.addHeader("Access-Control-Allow-Methods","GET,POST,PUT,DELETE,PATCH");
        if(request.getMethod().equals("OPTIONS")){
            response.setStatus(HttpServletResponse.SC_OK);//gol l backend ra baghi nakhod les donneés
        }
        else if (request.getRequestURI().equals("/login")){
            filterChain.doFilter(request,response);//passer au filter suivant
            return;
        }
        else {  //si le cas get ou post ou put ou delete en va faire la vérification de token 
            String jwt=request.getHeader(SecurityParams.HEADER_NAME);
            if(jwt==null || !jwt.startsWith(SecurityParams.HEADER_PREFIX )) {
                filterChain.doFilter(request,response);
                return;
            }
            JWTVerifier verifier=JWT.require(Algorithm.HMAC256(SecurityParams.SECRET)).build();                  //il faut signé le token 
            DecodedJWT decodedJWT= verifier.verify(jwt.substring(SecurityParams.HEADER_PREFIX.length()));
            String username=decodedJWT.getSubject();
            List<String> roles=decodedJWT.getClaims().get("roles").asList(String.class);
            Collection<GrantedAuthority> authorities=new ArrayList<>();
            roles.forEach(rn->{
                (authorities).add(new SimpleGrantedAuthority(rn));
            });
            UsernamePasswordAuthenticationToken user= new UsernamePasswordAuthenticationToken(username,null,authorities); //demande a spring d'authentifier l'utilisateur 
            SecurityContextHolder.getContext().setAuthentication(user);//authentifier cette user
            filterChain.doFilter(request,response);    //passer au filter suivants


        }

        }


}
