package com.rzero.cognitodemo.cognitodemo.config;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProvider;
import com.amazonaws.services.cognitoidp.AWSCognitoIdentityProviderClientBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AWSConfiguration {
    @Value("${rzero.aws.region}")
    String region;

    @Bean("awsCognito")
    public AWSCognitoIdentityProvider getCognitoProvider() {
        return AWSCognitoIdentityProviderClientBuilder.standard()
                .withRegion(Regions.fromName(region))
                .build();
    }

}
