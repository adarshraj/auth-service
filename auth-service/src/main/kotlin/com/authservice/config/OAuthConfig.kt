package com.authservice.config

import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithName
import java.util.Optional

@ConfigMapping(prefix = "auth.oauth")
interface OAuthConfig {

    fun google(): Provider
    fun github(): Provider

    interface Provider {
        @WithName("client-id")
        fun clientId(): Optional<String>

        @WithName("client-secret")
        fun clientSecret(): Optional<String>
    }
}
