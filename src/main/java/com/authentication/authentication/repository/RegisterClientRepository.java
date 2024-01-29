package com.authentication.authentication.repository;

import jakarta.annotation.Nullable;

public interface RegisterClientRepository {
    @Nullable

    RegisteredClient findById(String id);
    @Nullable
    RegisteredClient findByClientId(String clientId);
}
