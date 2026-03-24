package com.authservice.config

import io.smallrye.config.ConfigMapping
import io.smallrye.config.WithDefault
import io.smallrye.config.WithName

@ConfigMapping(prefix = "auth.oauth")
interface OAuthConfig {

    fun google(): Provider
    fun github(): Provider

    interface Provider {
        @WithName("client-id")
        @WithDefault("")
        fun clientId(): String

        @WithName("client-secret")
        @WithDefault("")
        fun clientSecret(): String
    }
}
