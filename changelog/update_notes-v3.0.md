# Changelog

---

## \[3.0.0] – 2025‑06‑08

### Added

* **Vault streaming**: Real-time encrypted data handling, minimizing plaintext exposure.
* Enhanced GUI interface, combining usability of KeyGuard 2.0 with advanced security features from 3.0.
* Advanced memory management via `SecureMemory` for handling sensitive information securely.
* Flatpak support for Linux distribution, ensuring sandboxed execution.
* Robust protection against memory dumps and debugging attacks.
* Automatic Argon2 parameter tuning for optimal security-performance balance.

### Changed

* Refactored internal architecture for modularity and maintainability.
* Improved zeroization technique: all secrets are securely wiped immediately after usage.
* Reimplemented secure logging, ensuring no sensitive data is ever stored in logs.
* Vault re-encryption now occurs seamlessly when changing the master password, enhancing security and convenience.

### Fixed

* Fixed GUI responsiveness issues when handling large vault files.
* Corrected rare errors during master password change affecting vault re-encryption integrity.
* Resolved inconsistencies in the memory obfuscation of sensitive keys.

### Security

* Significant improvements through **KeyObfuscator 2.0**, enhancing resistance against RAM inspection attacks.
* Strengthened Argon2id usage with dynamic difficulty adjustment.
* Implemented safeguards against double-free vulnerabilities in memory management.

---

## \[1.5.2] – 2025‑05‑18

### Added

* **KeyObfuscator** implementado para proteger as chaves criptográficas na memória, dificultando ataques por inspeção de RAM.
* Método aprimorado de segurança `wipe()` em `SecureBytes` para sobrescrever dados sensíveis com bytes aleatórios antes da zeroização final.
* Funcionalidade para **alteração segura da senha-mestra**, incluindo recriptografia automática do vault com novo salt e nova chave derivada.
* Menu interativo com a opção "Trocar Senha".
* Janela de visualização detalhada das senhas no Vault com proteção contra exposição involuntária (senha mascarada por padrão, exibindo no máximo 16 caracteres).
* Atualização do log de erros para arquivo **`logKeyGuard.log`** armazenado em pasta `.keyguard`.

### Changed

* Visualização principal do Vault agora mascara sempre as senhas para evitar exposição desnecessária.
* Arquivo de log renomeado de `keyguard` para **`logKeyGuard.log`** para melhor clareza e organização.
* Estrutura de segurança interna do arquivo criptografado otimizada, garantindo nonce determinístico de 96 bits derivado com HMAC-SHA-256 e autenticado por AAD.
* Melhor gerenciamento de memória com zeroização explícita e técnicas de obfuscação de chaves em memória.

### Fixed

* Corrigido erro `AttributeError: '_tkinter.tkapp' object has no attribute '_pw'` ao cancelar a janela de senha-mestra inicial.
* Corrigida a exibição da senha detalhada, garantindo que o botão "👁" funcione corretamente mesmo com senhas longas.

### Security

* Fortalecimento considerável da segurança do Vault com implementação do **KeyObfuscator**, protegendo chaves criptográficas contra extração indevida.
* Zeroização aprimorada de dados sensíveis na memória utilizando o método `wipe()`.
* Garantia adicional de integridade e confidencialidade das senhas armazenadas com a recriptografia segura ao alterar a senha-mestra.

---

## \[1.3.2] – 2025‑05‑18

### Added

* Implementação de **AAD (Associated Data)**.
* Nonce determinístico derivado por HMAC-SHA-256.
* Zeroização explícita com classe `SecureBytes`.
* Botão **"Excluir"** no Vault.

### Changed

* Cabeçalho com versão explícita (`"v": 2`).
* Segurança aprimorada do arquivo criptografado.

### Fixed

* Correção do uso inconsistente da variável de senha mestra (`self._password` para `self._pw`).
* Reintrodução correta dos atalhos:

  * <kbd>Ctrl + G</kbd>: Gerar nova senha.
  * <kbd>Ctrl + C</kbd>: Copiar senha.
  * <kbd>Ctrl + L</kbd>: Limpar senha.
  * <kbd>Esc</kbd>: Fechar aplicativo.

### Security

* Resistência aprimorada a ataques de força bruta e replay com parâmetros robustos de Argon2id e nonce determinístico autenticado por AAD.

---

## \[1.1.0] – 2025‑05‑18

### Added

* Botão "Limpar" com atalho <kbd>Ctrl + L</kbd>.

### Changed

* Removida validação rígida do campo Comprimento.

### Removed

* Cópia automática ao gerar senha.
* Janelas pop-up (`Messagebox`).

### Fixed

* Corrigido funcionamento do botão "Limpar".

### Security

* Redução do tempo de exposição de senhas.

---

## \[1.0.0] – 2025‑05‑17

### Added

* Versão inicial funcional.

---

**Legend**

* **Added** – Funcionalidade nova.
* **Changed** – Alteração na funcionalidade existente.
* **Removed** – Funcionalidade removida.
* **Fixed** – Correção de erro.
* **Security** – Melhorias relacionadas à segurança.

---
