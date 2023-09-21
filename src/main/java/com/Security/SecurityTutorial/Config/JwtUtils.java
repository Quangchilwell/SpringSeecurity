package com.Security.SecurityTutorial.Config;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtUtils {
	private String jwtSigningKey = "secret";
	
	// Trích xuất tên đn
	public String extractUsername(String token)
	{
		// In trả ra username bằng cách lấy Subject của claim
		return extractClaim(token, Claims::getSubject);
	}
	
	public Date extractExpiration(String token) {
		// Trả ra ngày hết hạn của token
		return extractClaim(token, Claims::getExpiration);
	}
	
	public boolean hasClaim(String token, String claimName)
	{
		final Claims claims = extractAllClaims(token);
		return claims.get(claimName) != null;
	}
	
	public<T> T extractClaim(String token, Function<Claims, T> claimsResolver)
	{
		// Trả ra một đối tượng
		// clams:{sub=q@gmail.com, exp=1680748022, iat=1680661622, authorities=[{authority=ROLE_ADMIN}]}
		final Claims claims = extractAllClaims(token);
		return claimsResolver.apply(claims);
	}
	
	private Claims extractAllClaims(String token)
	{
		// {sub=q@gmail.com, exp=1680752663, iat=1680666263, authorities=[{authority=ROLE_ADMIN}]}
		return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();
	}
	
	private Boolean isTokenExprired(String token)
	{
		return extractExpiration(token).before(new Date());
	}
	
	// Lấy ra chuỗi token
	public String generateToken(UserDetails userDetails)
	{
		System.out.println("Sinh ra token");
		Map<String, Object> claims = new HashMap<String, Object>();
		return createToken(claims, userDetails);
	}
	
	// Tạo ra token, cùng các cấu hình như ngày tạo, ngày hết hạn, thuật toán mã hóa chữ kí...
	private String createToken(Map<String, Object> claims, UserDetails userDetails)
	{
		return Jwts.builder().setClaims(claims)
				.setSubject(userDetails.getUsername())
				.claim("authorities", userDetails.getAuthorities())
				.setIssuedAt(new Date(System.currentTimeMillis()))
				.setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
				.signWith(SignatureAlgorithm.HS256, jwtSigningKey).compact();
	}
	
	public Boolean isTokenValid(String token, UserDetails userDetails)
	{
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExprired(token));
	}
}
