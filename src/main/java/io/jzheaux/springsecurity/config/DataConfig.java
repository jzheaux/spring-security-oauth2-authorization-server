package io.jzheaux.springsecurity.config;

import java.time.Duration;

import com.github.benmanes.caffeine.cache.Caffeine;

import org.springframework.cache.Cache;
import org.springframework.cache.caffeine.CaffeineCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class DataConfig {
	@Bean
	Cache accessTokenCache() {
		return new CaffeineCache("access_tokens", Caffeine.newBuilder()
				.expireAfterWrite(Duration.ofHours(1))
				.maximumSize(1_000_000)
				.build());
	}

	@Bean
	Cache refreshTokenCache() {
		return new CaffeineCache("refresh_tokens", Caffeine.newBuilder()
				.expireAfterWrite(Duration.ofDays(1))
				.maximumSize(1_000_000)
				.build());
	}

	@Bean
	Cache authorizationCodeCache() {
		return new CaffeineCache("authorization_code", Caffeine.newBuilder()
				.expireAfterWrite(Duration.ofMinutes(2))
				.maximumSize(1_000_000)
				.build());
	}

}
