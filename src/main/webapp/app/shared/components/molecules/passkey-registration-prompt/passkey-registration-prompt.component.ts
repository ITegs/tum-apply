import { Component, computed, effect, inject, signal } from '@angular/core';
import { AccountService } from 'app/core/auth/account.service';
import { AuthFacadeService } from 'app/core/auth/auth-facade.service';
import { KeycloakAuthenticationService } from 'app/core/auth/keycloak-authentication.service';
import { ButtonComponent } from 'app/shared/components/atoms/button/button.component';
import { CheckboxComponent } from 'app/shared/components/atoms/checkbox/checkbox.component';
import { DialogComponent } from 'app/shared/components/atoms/dialog/dialog.component';
import { TranslateDirective } from 'app/shared/language';

@Component({
  selector: 'jhi-passkey-registration-prompt',
  standalone: true,
  imports: [DialogComponent, CheckboxComponent, ButtonComponent, TranslateDirective],
  templateUrl: './passkey-registration-prompt.component.html',
})
export class PasskeyRegistrationPromptComponent {
  private static readonly PASSKEY_PROMPT_NEVER_ASK_AGAIN_KEY = 'auth.passkey.prompt.neverAskAgain';

  readonly accountService = inject(AccountService);
  readonly authFacade = inject(AuthFacadeService);
  readonly keycloakAuthenticationService = inject(KeycloakAuthenticationService);

  readonly loggedIn = computed(() => this.accountService.signedIn());
  readonly visible = signal(false);
  readonly neverAskAgain = signal(false);
  readonly busy = signal(false);
  private readonly shownThisSession = signal(false);
  private readonly hasPasskeyConfigured = signal<boolean | null>(null);
  private readonly checkingPasskeys = signal(false);

  constructor() {
    effect(() => {
      if (!this.canEvaluatePrompt()) {
        return;
      }

      if (this.hasPasskeyConfigured() === null) {
        if (!this.checkingPasskeys()) {
          void this.loadPasskeyConfiguration();
        }
        return;
      }

      if (this.shouldShowPrompt()) {
        this.visible.set(true);
        this.shownThisSession.set(true);
      }
    });
  }

  close(): void {
    this.persistPreference();
    this.visible.set(false);
  }

  async registerPasskey(): Promise<void> {
    this.persistPreference();
    this.visible.set(false);
    this.busy.set(true);
    try {
      await this.authFacade.registerPasskey();
      this.hasPasskeyConfigured.set(true);
    } finally {
      this.busy.set(false);
    }
  }

  private canEvaluatePrompt(): boolean {
    return (
      this.loggedIn() &&
      this.keycloakAuthenticationService.isLoggedIn() &&
      !this.shownThisSession() &&
      localStorage.getItem(PasskeyRegistrationPromptComponent.PASSKEY_PROMPT_NEVER_ASK_AGAIN_KEY) !== 'true'
    );
  }

  private shouldShowPrompt(): boolean {
    return this.canEvaluatePrompt() && this.hasPasskeyConfigured() === false;
  }

  private async loadPasskeyConfiguration(): Promise<void> {
    this.checkingPasskeys.set(true);
    try {
      const passkeys = await this.keycloakAuthenticationService.listPasskeys();
      this.hasPasskeyConfigured.set(passkeys.length > 0);
    } catch {
      // Do not show a setup prompt when passkey status cannot be determined.
      this.hasPasskeyConfigured.set(true);
    } finally {
      this.checkingPasskeys.set(false);
    }
  }

  private persistPreference(): void {
    if (!this.neverAskAgain()) {
      return;
    }
    localStorage.setItem(PasskeyRegistrationPromptComponent.PASSKEY_PROMPT_NEVER_ASK_AGAIN_KEY, 'true');
  }
}
