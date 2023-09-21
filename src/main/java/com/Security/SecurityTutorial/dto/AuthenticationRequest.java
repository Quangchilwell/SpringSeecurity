package com.Security.SecurityTutorial.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class AuthenticationRequest {
	
	private String email;
	private String password;
}
