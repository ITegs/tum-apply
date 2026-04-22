import { Component, computed, inject, signal } from '@angular/core';
import { TranslateModule } from '@ngx-translate/core';
import { ToastService } from 'app/service/toast-service';
import { AuthFacadeService } from 'app/core/auth/auth-facade.service';
import { KeycloakAuthenticationService } from 'app/core/auth/keycloak-authentication.service';
import { ButtonComponent } from 'app/shared/components/atoms/button/button.component';
import { ConfirmDialog } from 'app/shared/components/atoms/confirm-dialog/confirm-dialog';
import TranslateDirective from 'app/shared/language/translate.directive';
import { PasskeyCredentialSummary } from 'app/core/auth/models/auth.model';

@Component({
  selector: 'jhi-passkey-settings',
  standalone: true,
  imports: [ButtonComponent, ConfirmDialog, TranslateDirective, TranslateModule],
  templateUrl: './passkey-settings.component.html',
})
export class PasskeySettingsComponent {
  readonly passkeys = signal<PasskeyCredentialSummary[]>([]);
  readonly loaded = signal(false);
  readonly creating = signal(false);
  readonly removingId = signal<string | null>(null);
  readonly canManagePasskeys = signal(false);
  readonly hasPasskeys = computed(() => this.passkeys().length > 0);

  private readonly authFacade = inject(AuthFacadeService);
  private readonly keycloakAuthenticationService = inject(KeycloakAuthenticationService);
  private readonly toastService = inject(ToastService);
  private readonly dateFormatter = new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });

  constructor() {
    this.canManagePasskeys.set(this.keycloakAuthenticationService.isLoggedIn());
    void this.loadPasskeys();
  }

  async createPasskey(): Promise<void> {
    if (this.creating() || !this.canManagePasskeys()) {
      return;
    }

    this.creating.set(true);
    try {
      await this.authFacade.registerPasskey();
      await this.loadPasskeys();
    } finally {
      this.creating.set(false);
    }
  }

  async removePasskey(id: string): Promise<void> {
    if (this.removingId() !== null || !this.canManagePasskeys()) {
      return;
    }

    this.removingId.set(id);
    try {
      await this.keycloakAuthenticationService.removePasskey(id);
      this.passkeys.update(passkeys => passkeys.filter(passkey => passkey.id !== id));
      this.toastService.showSuccessKey('settings.passkeys.removed');
    } catch {
      this.toastService.showErrorKey('settings.passkeys.removeFailed');
    } finally {
      this.removingId.set(null);
    }
  }

  passkeyLabel(passkey: PasskeyCredentialSummary, index: number): string {
    const label = passkey.label?.trim();
    if (label) {
      return label;
    }
    return `Passkey ${index + 1}`;
  }

  createdAt(passkey: PasskeyCredentialSummary): string | null {
    if (passkey.createdDate == null) {
      return null;
    }

    try {
      return this.dateFormatter.format(passkey.createdDate);
    } catch {
      return null;
    }
  }

  removeDisabled(passkeyId: string): boolean {
    const removingId = this.removingId();
    return removingId !== null && removingId !== passkeyId;
  }

  private async loadPasskeys(): Promise<void> {
    if (!this.canManagePasskeys()) {
      this.passkeys.set([]);
      this.loaded.set(true);
      return;
    }

    try {
      this.passkeys.set(await this.keycloakAuthenticationService.listPasskeys());
    } catch {
      this.toastService.showErrorKey('settings.passkeys.loadFailed');
    } finally {
      this.loaded.set(true);
    }
  }
}
