package com.mildo.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

//    @Override
//    public void addCorsMappings(CorsRegistry registry) {
//        registry.addMapping("/**")
//                .allowedOrigins("https://school.programmers.co.kr", "https://www.podofarm.xyz", "https://podofarm.xyz",
//                        "http://mildo.xyz", "http://www.mildo.xyz", "https://mildo.xyz", "https://www.mildo.xyz",
//                        "http://localhost:5173", "http://localhost:5174", "http://localhost:5175") // 허용할 도메인 설정
//                .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH")
////                .allowedHeaders("*")
//                .allowedHeaders("Content-Type", "Authorization", "X-Requested-With", "Accept") // 필요한 헤더 명시
//                .allowCredentials(true);
//    }


}
