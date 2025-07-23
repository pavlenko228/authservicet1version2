package com.t1.authservice.domain.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Schema(description = "Request Dto for registration")
public class RegistrationRequest {

    @Schema(description = "Login", example = "Jon Week")
    @Size(min = 8, max = 50, message = "Логин должно содержать от 5 до 50 символов")
    @NotBlank(message = "Login can't be empty")
    private String login;

    @Schema(description = "Email adress", example = "jondoe@gmail.com")
    @Size(min = 5, max = 255, message = "Адрес электронной почты должен содержать от 5 до 255 символов")
    @NotBlank(message = "Email adress can't be empty")
    @Email(message = "Email adress must be at format user@example.com")
    private String email;

    @Schema(description = "Password", example = "my_1secret1_password")
    @Size(min = 10, max = 255, message = "Длина пароля должна быть не более 255 символов")
    private String password;

}