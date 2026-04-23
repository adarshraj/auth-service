package com.authservice.config

import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithDefault
import io.smallrye.config.WithName

@ConfigMapping(prefix = "auth.rate-limit")
interface RateLimitConfig {

    @WithDefault("true")
    fun enabled(): Boolean

    @WithName("requests-per-minute")
    @WithDefault("60")
    fun requestsPerMinute(): Int
}
