package br.com.techne.hades.controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController{
	@RequestMapping("/")
	public String home(){
		return "Bem Vindo";
	}
}