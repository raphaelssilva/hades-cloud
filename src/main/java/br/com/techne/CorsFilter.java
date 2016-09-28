package br.com.techne;

import org.springframework.web.filter.*;
import org.springframework.stereotype.*;
import org.springframework.core.*;
import org.springframework.core.annotation.*;
import javax.servlet.*;
import javax.servlet.http.*;
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorsFilter implements Filter {
	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) {
		HttpServletResponse response = (HttpServletResponse) res;
		HttpServletRequest request = (HttpServletRequest) req;
	    response.setHeader("Access-Control-Allow-Origin", "*");
	    response.setHeader("Access-Control-Allow-Methods", "POST, PUT, GET, OPTIONS, DELETE");
	    response.setHeader("Access-Control-Allow-Headers", "x-requested-with");
	    response.setHeader("Access-Control-Max-Age", "3600");

	    if(request.getMethod() != "OPTIONS"){
	    	try{
  				chain.doFilter(request, response);
			}catch(Exception e){
  				e.printStackTrace();
			}
	      
	    } 
	}
	@Override
	public void init(FilterConfig filterConfig) {}
	@Override
	public void destroy() {}
}