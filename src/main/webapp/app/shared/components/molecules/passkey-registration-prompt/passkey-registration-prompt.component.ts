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

  private readonly accountService = inject(AccountService);
  private readonly authFacade = inject(AuthFacadeService);
  private readonly keycloakAuthenticationService = inject(KeycloakAuthenticationService);

  readonly loggedIn = computed(() => this.accountService.signedIn());
  readonly visible = signal(false);
  readonly neverAskAgain = signal(false);
  readonly busy = signal(false);
  private readonly shownThisSession = signal(false);

  constructor() {
    effect(() => {
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
    } finally {
      this.busy.set(false);
    }
  }

  private shouldShowPrompt(): boolean {
    return (
      this.loggedIn() &&
      this.keycloakAuthenticationService.isLoggedIn() &&
      !this.shownThisSession() &&
      localStorage.getItem(PasskeyRegistrationPromptComponent.PASSKEY_PROMPT_NEVER_ASK_AGAIN_KEY) !== 'true'
    );
  }

  private persistPreference(): void {
    if (!this.neverAskAgain()) {
      return;
    }
    localStorage.setItem(PasskeyRegistrationPromptComponent.PASSKEY_PROMPT_NEVER_ASK_AGAIN_KEY, 'true');
  }
}
