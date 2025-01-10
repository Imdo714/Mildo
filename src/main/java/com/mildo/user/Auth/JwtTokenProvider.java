package com.mildo.user.Auth;

import com.mildo.user.Vo.UserVO;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Base64;
import java.util.Date;

@Slf4j
@Component
public class JwtTokenProvider {

    // public을 사용해서 JwtAuthenticationFilter 에도 참조 할 수 있게 만듬
    public static final String SECRET_KEY = Base64.getEncoder().encodeToString(Keys.secretKeyFor(SignatureAlgorithm.HS256).getEncoded());
    public static final String REFRESH_TOKEN_SECRET_KEY = Base64.getEncoder().encodeToString(Keys.secretKeyFor(SignatureAlgorithm.HS512).getEncoded());

    // accessToken 생성
    public static String createAccessToken(String userId) {

        return Jwts.builder()
                .setSubject(userId) // 유저 번호를 subject로 설정 // #G909
//                .claim("username", user.getUserName()) // 추가 정보 저장
                .setIssuedAt(new Date()) // 발급 시간 (현재 시간으로 자동 설정)
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60)) // 1시간 후 만료
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // 서명
                .compact();
    }

    // Access Token 만료 시간 반환 메서드
    public static Date getExpirationFromToken(String accessToken) {
        Claims claims = Jwts.parser()
                .setSigningKey(SECRET_KEY) // 서명 검증을 위한 키
                .parseClaimsJws(accessToken) // 토큰 파싱
                .getBody(); // Payload 추출

        return claims.getExpiration(); // 만료 시간 반환
    }

    // refresh Token 생성
    public static String createRefreshToken(String userId) {
        return Jwts.builder()
                .setSubject(userId) // 사용자 userId를 subject로 설정
                .setIssuedAt(new Date()) // 발급 시간
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 7)) // 7일 후 만료
                .signWith(SignatureAlgorithm.HS512, REFRESH_TOKEN_SECRET_KEY) // 서명
                .compact();
    }

    // refresh Token 만료 시간 반환 메서드
    public static Date getExpirationFromRefreshToken(String accessToken) {
        Claims claims = Jwts.parser()
                .setSigningKey(REFRESH_TOKEN_SECRET_KEY) // 서명 검증을 위한 키
                .parseClaimsJws(accessToken) // 토큰 파싱
                .getBody(); // Payload 추출

        return claims.getExpiration(); // 만료 시간 반환
    }

}
