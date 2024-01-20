package it.magiavventure.jwt.model;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;
import java.util.UUID;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {

    @NotNull
    private UUID id;

    @NotNull
    private String name;

    private List<Category> preferredCategories;

    @NotEmpty
    private List<Authority> authorities;

}
