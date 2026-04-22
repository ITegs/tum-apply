import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AuthFacadeService } from 'app/core/auth/auth-facade.service';
import { KeycloakAuthenticationService } from 'app/core/auth/keycloak-authentication.service';
import { PasskeyCredentialSummary } from 'app/core/auth/models/auth.model';
import { ToastService } from 'app/service/toast-service';
import { PasskeySettingsComponent } from 'app/shared/settings/passkey-settings/passkey-settings.component';
import { provideFontAwesomeTesting } from 'util/fontawesome.testing';
import { createToastServiceMock } from 'util/toast-service.mock';
import { provideTranslateMock } from 'util/translate.mock';

describe('PasskeySettingsComponent', () => {
  let fixture: ComponentFixture<PasskeySettingsComponent>;
  let component: PasskeySettingsComponent;

  let authFacadeMock: {
    registerPasskey: ReturnType<typeof vi.fn>;
  };
  let keycloakAuthenticationServiceMock: {
    isLoggedIn: ReturnType<typeof vi.fn>;
    listPasskeys: ReturnType<typeof vi.fn>;
    removePasskey: ReturnType<typeof vi.fn>;
  };
  let toastServiceMock: ReturnType<typeof createToastServiceMock>;

  const existingPasskeys: PasskeyCredentialSummary[] = [
    { id: 'passkey-1', label: 'MacBook Pro', createdDate: 1_710_000_000_000 },
    { id: 'passkey-2', label: null, createdDate: null },
  ];

  const createComponent = async (): Promise<void> => {
    fixture = TestBed.createComponent(PasskeySettingsComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  };

  beforeEach(async () => {
    authFacadeMock = {
      registerPasskey: vi.fn().mockResolvedValue(undefined),
    };
    keycloakAuthenticationServiceMock = {
      isLoggedIn: vi.fn().mockReturnValue(true),
      listPasskeys: vi.fn().mockResolvedValue([]),
      removePasskey: vi.fn().mockResolvedValue(undefined),
    };
    toastServiceMock = createToastServiceMock();

    await TestBed.configureTestingModule({
      imports: [PasskeySettingsComponent],
      providers: [
        { provide: AuthFacadeService, useValue: authFacadeMock },
        { provide: KeycloakAuthenticationService, useValue: keycloakAuthenticationServiceMock },
        { provide: ToastService, useValue: toastServiceMock },
        provideTranslateMock(),
        provideFontAwesomeTesting(),
      ],
    }).compileComponents();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('should load passkeys on init when the user can manage them', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockResolvedValue(existingPasskeys);

    await createComponent();

    expect(component.canManagePasskeys()).toBe(true);
    expect(component.loaded()).toBe(true);
    expect(component.loadFailed()).toBe(false);
    expect(component.passkeys()).toEqual(existingPasskeys);
    expect(keycloakAuthenticationServiceMock.listPasskeys).toHaveBeenCalledOnce();
    expect(fixture.nativeElement.textContent).toContain('MacBook Pro');
  });

  it('should show the unavailable state and skip loading when the user is not logged in with keycloak', async () => {
    keycloakAuthenticationServiceMock.isLoggedIn.mockReturnValue(false);

    await createComponent();

    expect(component.canManagePasskeys()).toBe(false);
    expect(component.loaded()).toBe(true);
    expect(component.passkeys()).toEqual([]);
    expect(component.loadFailed()).toBe(false);
    expect(keycloakAuthenticationServiceMock.listPasskeys).not.toHaveBeenCalled();
    expect(fixture.nativeElement.textContent).toContain('settings.passkeys.unavailable.title');
  });

  it('should show an error state and toast when loading passkeys fails', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockRejectedValue(new Error('load failed'));

    await createComponent();

    expect(component.loaded()).toBe(true);
    expect(component.loadFailed()).toBe(true);
    expect(component.passkeys()).toEqual([]);
    expect(toastServiceMock.showErrorKey).toHaveBeenCalledWith('settings.passkeys.loadFailed');
    expect(fixture.nativeElement.textContent).toContain('settings.passkeys.error.title');
  });

  it('should create a passkey and reload the list', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockResolvedValueOnce([]).mockResolvedValueOnce(existingPasskeys);

    await createComponent();
    await component.createPasskey();
    fixture.detectChanges();

    expect(authFacadeMock.registerPasskey).toHaveBeenCalledOnce();
    expect(keycloakAuthenticationServiceMock.listPasskeys).toHaveBeenCalledTimes(2);
    expect(component.creating()).toBe(false);
    expect(component.passkeys()).toEqual(existingPasskeys);
  });

  it('should remove a passkey and keep the remaining entries', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockResolvedValue(existingPasskeys);

    await createComponent();
    await component.removePasskey('passkey-1');
    fixture.detectChanges();

    expect(keycloakAuthenticationServiceMock.removePasskey).toHaveBeenCalledWith('passkey-1');
    expect(component.passkeys()).toEqual([{ id: 'passkey-2', label: null, createdDate: null }]);
    expect(component.removingId()).toBeNull();
    expect(toastServiceMock.showSuccessKey).toHaveBeenCalledWith('settings.passkeys.removed');
  });

  it('should show an error toast and reset removing state when removing a passkey fails', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockResolvedValue(existingPasskeys);
    keycloakAuthenticationServiceMock.removePasskey.mockRejectedValue(new Error('remove failed'));

    await createComponent();
    await component.removePasskey('passkey-1');

    expect(component.passkeys()).toEqual(existingPasskeys);
    expect(component.removingId()).toBeNull();
    expect(toastServiceMock.showErrorKey).toHaveBeenCalledWith('settings.passkeys.removeFailed');
  });

  it('should use fallback labels and safe date formatting helpers', async () => {
    await createComponent();

    expect(component.passkeyLabel({ id: 'passkey-3', label: '   ', createdDate: null }, 1)).toBe('Passkey 2');
    expect(component.createdAt({ id: 'passkey-3', label: null, createdDate: Number.NaN })).toBeNull();
    expect(component.removeDisabled('passkey-1')).toBe(false);

    component.removingId.set('passkey-2');

    expect(component.removeDisabled('passkey-1')).toBe(true);
    expect(component.removeDisabled('passkey-2')).toBe(false);
  });
});
