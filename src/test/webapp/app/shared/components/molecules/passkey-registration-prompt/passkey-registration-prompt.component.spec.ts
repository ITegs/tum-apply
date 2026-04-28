import { ComponentFixture, TestBed } from '@angular/core/testing';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AccountServiceMock, createAccountServiceMock, provideAccountServiceMock } from 'util/account.service.mock';
import { AuthFacadeService } from 'app/core/auth/auth-facade.service';
import { KeycloakAuthenticationService } from 'app/core/auth/keycloak-authentication.service';
import { provideTranslateMock } from 'util/translate.mock';
import { PasskeyRegistrationPromptComponent } from 'app/shared/components/molecules/passkey-registration-prompt/passkey-registration-prompt.component';

describe('PasskeyRegistrationPromptComponent', () => {
  const promptPreferenceId = 'ui_pref_hide_passkey_prompt';

  let fixture: ComponentFixture<PasskeyRegistrationPromptComponent>;
  let component: PasskeyRegistrationPromptComponent;
  let accountServiceMock: AccountServiceMock;
  let authFacadeMock: {
    registerPasskey: ReturnType<typeof vi.fn>;
  };
  let keycloakAuthenticationServiceMock: {
    isLoggedIn: ReturnType<typeof vi.fn>;
    listPasskeys: ReturnType<typeof vi.fn>;
  };

  const createComponent = async (): Promise<void> => {
    fixture = TestBed.createComponent(PasskeyRegistrationPromptComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
    await fixture.whenStable();
    fixture.detectChanges();
  };

  beforeEach(async () => {
    accountServiceMock = createAccountServiceMock(true);
    authFacadeMock = {
      registerPasskey: vi.fn().mockResolvedValue(undefined),
    };
    keycloakAuthenticationServiceMock = {
      isLoggedIn: vi.fn().mockReturnValue(true),
      listPasskeys: vi.fn().mockResolvedValue([]),
    };

    localStorage.removeItem(promptPreferenceId);

    await TestBed.configureTestingModule({
      imports: [PasskeyRegistrationPromptComponent],
      providers: [
        provideAccountServiceMock(accountServiceMock),
        { provide: AuthFacadeService, useValue: authFacadeMock },
        { provide: KeycloakAuthenticationService, useValue: keycloakAuthenticationServiceMock },
        provideTranslateMock(),
      ],
    }).compileComponents();
  });

  afterEach(() => {
    localStorage.removeItem(promptPreferenceId);
    vi.restoreAllMocks();
  });

  it('should show the prompt when user is logged in and has no passkeys', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockResolvedValue([]);

    await createComponent();

    expect(keycloakAuthenticationServiceMock.listPasskeys).toHaveBeenCalledOnce();
    expect(component.visible()).toBe(true);
  });

  it('should keep the prompt hidden when passkeys are already configured', async () => {
    keycloakAuthenticationServiceMock.listPasskeys.mockResolvedValue([{ id: 'pk-1', label: 'Laptop', createdDate: null }]);

    await createComponent();

    expect(keycloakAuthenticationServiceMock.listPasskeys).toHaveBeenCalledOnce();
    expect(component.visible()).toBe(false);
  });

  it('should not evaluate prompt when hidden by stored preference', async () => {
    localStorage.setItem(promptPreferenceId, 'true');

    await createComponent();

    expect(keycloakAuthenticationServiceMock.listPasskeys).not.toHaveBeenCalled();
    expect(component.visible()).toBe(false);
  });

  it('should persist preference and close when neverAskAgain is enabled', async () => {
    await createComponent();
    component.neverAskAgain.set(true);

    component.close();

    expect(localStorage.getItem(promptPreferenceId)).toBe('true');
    expect(component.visible()).toBe(false);
  });

  it('should register passkey, hide prompt and reset busy state', async () => {
    await createComponent();

    await component.registerPasskey();

    expect(authFacadeMock.registerPasskey).toHaveBeenCalledOnce();
    expect(component.busy()).toBe(false);
    expect(component.visible()).toBe(false);
  });
});
