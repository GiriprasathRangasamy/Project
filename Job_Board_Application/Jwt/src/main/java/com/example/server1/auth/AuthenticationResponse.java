package com.example.server1.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class AuthenticationResponse {
    @JsonProperty("access_token")
    private String accessToken;
    private String alert;
}
