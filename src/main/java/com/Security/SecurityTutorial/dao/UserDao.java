package com.Security.SecurityTutorial.dao;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

@Repository
public class UserDao {
	private static final List<UserDetails> APPLICATION_USERS = Arrays.asList(
			new User("q@gmail.com", "123", Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))),
			new User("tr@gmail.com", "123", Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")))
	);
	
	public UserDetails findUserByEmail(String email) {
		System.out.println("DAO: " + email);
		return APPLICATION_USERS
				.stream()
				.filter(u -> u.getUsername().equals(email))
				.findFirst()
				.orElseThrow(() -> new UsernameNotFoundException("No user was found"));
	}
		
}
