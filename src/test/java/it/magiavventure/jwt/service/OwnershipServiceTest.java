package it.magiavventure.jwt.service;

import it.magiavventure.common.error.MagiavventureException;
import it.magiavventure.jwt.config.AppContext;
import it.magiavventure.mongo.entity.EUser;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;
import java.util.UUID;

@ExtendWith(MockitoExtension.class)
@DisplayName("Ownership service tests")
class OwnershipServiceTest {
    @InjectMocks
    private OwnershipService ownershipService;
    @Spy
    private AppContext appContext = new AppContext();

    @Test
    @DisplayName("Given id value and user with different id throw ownership exception")
    void givenIdValueAndUserWithDifferentId_throwOwnershipException() {
        UUID id = UUID.randomUUID();
        EUser eUser = EUser.builder().id(UUID.randomUUID()).authorities(List.of(OwnershipService.USER_AUTHORITY)).build();
        appContext.setUser(eUser);

        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> ownershipService.validateOwnership(id));

        Assertions.assertNotNull(exception);
        Assertions.assertEquals("ownership", exception.getError().getKey());
    }

    @Test
    @DisplayName("Given id value and user with same id not throw ownership exception")
    void givenIdValueAndUserWithSameId_notThrowOwnershipException() {
        UUID id = UUID.randomUUID();
        EUser eUser = EUser.builder().id(id).authorities(List.of(OwnershipService.USER_AUTHORITY)).build();
        appContext.setUser(eUser);

        Assertions.assertDoesNotThrow(() -> ownershipService.validateOwnership(id));
    }

    @Test
    @DisplayName("Given id value and user with different id but is admin not throw ownership exception")
    void givenIdValueAndUserWithDifferentIdButIsAdmin_notThrowOwnershipException() {
        UUID id = UUID.randomUUID();
        EUser eUser = EUser.builder().authorities(List.of(OwnershipService.ADMIN_AUTHORITY)).build();
        appContext.setUser(eUser);

        Assertions.assertDoesNotThrow(() -> ownershipService.validateOwnership(id));
    }

    @Test
    @DisplayName("Given id value and null user throw not authenticated exception")
    void givenIdValueAndNullUser_throwNoOwnershipCheckException() {
        UUID id = UUID.randomUUID();
        appContext.setUser(null);

        MagiavventureException noOwnershipException = Assertions.assertThrows(MagiavventureException.class,
                () -> ownershipService.validateOwnership(id));

        Assertions.assertNotNull(noOwnershipException);
        Assertions.assertEquals("not-authenticated", noOwnershipException.getError().getKey());
    }

    @Test
    @DisplayName("Given name value and user with different name throw ownership exception")
    void givenNameValueAndUserWithDifferentName_throwOwnershipException() {
        String name = "name";
        EUser eUser = EUser.builder().authorities(List.of(OwnershipService.USER_AUTHORITY)).name("name2").build();
        appContext.setUser(eUser);

        MagiavventureException exception = Assertions.assertThrows(MagiavventureException.class,
                () -> ownershipService.validateOwnership(name));

        Assertions.assertNotNull(exception);
        Assertions.assertEquals("ownership", exception.getError().getKey());
    }

    @Test
    @DisplayName("Given name value and user with same name not throw ownership exception")
    void givenNameValueAndUserWithSameName_notThrowOwnershipException() {
        String name = "name";
        EUser eUser = EUser.builder().authorities(List.of(OwnershipService.USER_AUTHORITY)).name(name).build();
        appContext.setUser(eUser);

        Assertions.assertDoesNotThrow(() -> ownershipService.validateOwnership(name));
    }

    @Test
    @DisplayName("Given name value and user with different name but is admin not throw ownership exception")
    void givenNameValueAndUserWithDifferentNameButIsAdmin_notThrowOwnershipException() {
        String name = "name";
        EUser eUser = EUser.builder().authorities(List.of(OwnershipService.ADMIN_AUTHORITY)).name(name).build();
        appContext.setUser(eUser);

        Assertions.assertDoesNotThrow(() -> ownershipService.validateOwnership(name));
    }

    @Test
    @DisplayName("Given name value and null user throw not authenticated exception")
    void givenNameValueAndNullUser_throwNoOwnershipCheckException() {
        String name = "name";
        appContext.setUser(null);

        MagiavventureException noOwnershipException = Assertions.assertThrows(MagiavventureException.class,
                () -> ownershipService.validateOwnership(name));

        Assertions.assertNotNull(noOwnershipException);
        Assertions.assertEquals("not-authenticated", noOwnershipException.getError().getKey());
    }

}
