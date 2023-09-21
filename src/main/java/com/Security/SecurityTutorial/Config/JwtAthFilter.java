package com.Security.SecurityTutorial.Config;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.Security.SecurityTutorial.dao.UserDao;

import lombok.RequiredArgsConstructor;


@Component
@RequiredArgsConstructor
public class JwtAthFilter extends OncePerRequestFilter{

	@Autowired UserDao userDao;
	@Autowired JwtUtils jwtUtils;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, 
				HttpServletResponse response, 
				FilterChain filterChain)
			throws ServletException, IOException {
		// Sinh ra token kem tu Bearer.
		final String authHeader = request.getHeader(AUTHORIZATION);
		final String userEmail;
		final String JwtToken;
		
		// Khi moi dang nhap thi se ko co authHeader
		if(authHeader == null || !authHeader.startsWith("Bearer")) {
			filterChain.doFilter(request, response);
			return;
		}
		
		// Lấy chuỗi bearer bằng cách bỏ từ Bearer và 1 dấu cách
		JwtToken = authHeader.substring(7);
		userEmail = jwtUtils.extractUsername(JwtToken);
		System.out.println(authHeader);
		if(userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
			UserDetails userDetails = userDao.findUserByEmail(userEmail);
			
			if(jwtUtils.isTokenValid(JwtToken, userDetails)) {
				UsernamePasswordAuthenticationToken authToken = 
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				System.out.println(authToken);
				authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(authToken);
			}
		}
		filterChain.doFilter(request, response);
	}
}
