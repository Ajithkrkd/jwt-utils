package com.ajith.jwtutilpackage.jwt;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.StringUtils;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.function.Function;


public class JwtService {
    @Value ( "${application.security.jwt.secret-key}" )
    private static String secretKey;
    @Value ( "${application.security.jwt.expiration}" )
    private static long jwtExpiration ;

    @Value ( "${application.security.jwt.refresh-token.expiration}" )
    private static long refreshExpiration ;

    public static String extractUsername (String token) {
        return extractClaim (token, Claims::getSubject);
    }


    public static <T>T extractClaim (String token, Function < Claims, T > claimsResolver) {
        final Claims claims = extractAllClaims ( token );
        return claimsResolver.apply ( claims );
    }


    public List <String> extractRolesFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(getSigningKey())
                .parseClaimsJws(token)
                .getBody();

        return (List<String>) claims.get("roles");
    }

    public boolean isTokenExpired (String token) {
        return extractExpiration(token).before(new Date());
    }

    public Date extractExpiration (String token) {
        return extractClaim ( token ,Claims::getExpiration );
    }



    private static Claims extractAllClaims (String token) {
        return Jwts
                .parserBuilder ()
                .setSigningKey ( getSigningKey() )
                .build ()
                .parseClaimsJws ( token )
                .getBody ();
    }

    public static Key getSigningKey ( ) {
        byte[] keyBytes = Decoders.BASE64.decode (secretKey);
        return Keys.hmacShaKeyFor (keyBytes);
    }

    public static String getJWTFromRequest(HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        if( StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")){
            return bearerToken.substring(7);
        }
        return null;
    }
}