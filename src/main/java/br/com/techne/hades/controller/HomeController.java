package br.com.techne.hades.controller;

import org.springframework.web.bind.annotation.*;
@RestController
public class HomeController{
	//@CrossOrigin(origins = "http://localhost:8080")
	@RequestMapping("/")
	public String home(){
		return "Bem Vindo";
	}
}