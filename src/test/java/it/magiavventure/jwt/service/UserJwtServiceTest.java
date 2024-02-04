package it.magiavventure.jwt.service;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.mongo.entity.EUser;
import it.magiavventure.mongo.repository.UserRepository;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
@DisplayName("User jwt service tests")
class UserJwtServiceTest {
    @InjectMocks
    private UserJwtService userJwtService;
    @Mock
    private UserRepository userRepository;

    @Test
    @DisplayName("Given id retrieve user")
    void givenId_retrieveUser_ok() {
        UUID id = UUID.randomUUID();

        Mockito.when(userRepository.findById(id))
                .thenReturn(Optional.of(EUser.builder().build()));

        EUser eUser = userJwtService.retrieveById(id);

        Mockito.verify(userRepository).findById(id);

        Assertions.assertNotNull(eUser);
    }

    @Test
    @DisplayName("Given wrong id retrieving user will throw exception")
    void givenWrongId_retrievingUser_throwException() {
        UUID id = UUID.randomUUID();

        Mockito.when(userRepository.findById(id))
                .thenReturn(Optional.empty());

        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> userJwtService.retrieveById(id));

        Assertions.assertNotNull(exception);
        Assertions.assertEquals("user-not-found", exception.getError().getKey());
        Assertions.assertIterableEquals(List.of(id.toString()), Arrays.asList(exception.getError().getArgs()));
    }

    @Test
    @DisplayName("Given user entity validate with ban expiration")
    void givenUserWithBanExpiration_validateUser_throwException() {
        EUser eUser = EUser.builder().banExpiration(LocalDateTime.now().plusDays(30)).build();

        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> userJwtService.validateUser(eUser));

        Assertions.assertNotNull(exception);
        Assertions.assertEquals("user-blocked", exception.getError().getKey());
    }

    @Test
    @DisplayName("Given user entity validate with expired ban")
    void givenUserWithExpiredBan_validateUser_ok() {
        EUser eUser = EUser.builder().banExpiration(LocalDateTime.now().minusDays(30)).build();

        Assertions.assertDoesNotThrow(() -> userJwtService.validateUser(eUser));
    }

    @Test
    @DisplayName("Given user entity validate with null ban expiration")
    void givenUserWithNullBanExpiration_validateUser_ok() {
        EUser eUser = EUser.builder().build();

        Assertions.assertDoesNotThrow(() -> userJwtService.validateUser(eUser));
    }

}
