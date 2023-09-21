package com.Security.SecurityTutorial.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.Security.SecurityTutorial.Config.JwtUtils;
import com.Security.SecurityTutorial.dao.UserDao;
import com.Security.SecurityTutorial.dto.AuthenticationRequest;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDao userDao;
	
	@Autowired
	private JwtUtils jwtUtils;
	
	@PostMapping("/authenticate")
	public ResponseEntity<String> authenticate(@RequestBody AuthenticationRequest request){
		System.out.println("Vào controller");
		// Truyền thông tin đăng nhập vào, nó sẽ lưu các thông tin cần thiết cho việc đăng nhập.
		// Các thông tin như pasword sẽ được bảo mật
		authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(request.getEmail(), request.getPassword())
		);
		
		UserDetails user = userDao.findUserByEmail(request.getEmail());
		if(user != null) {
			// Generate token
			return ResponseEntity.ok(jwtUtils.generateToken(user));
		}
		
		return ResponseEntity.status(400).body("Some error has occured");
	}
}
