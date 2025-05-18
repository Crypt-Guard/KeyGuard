# Changelog

---

## \[1.3.2] – 2025‑05‑18

### Added

* Implementação de **AAD (Associated Data)** para proteger o cabeçalho contra alterações não autorizadas.
* Nonce de 96 bits determinístico derivado por HMAC-SHA-256, garantindo unicidade absoluta.
* Zeroização explícita e segura na memória usando classe `SecureBytes`.
* `mlock` opcional para fixar a chave criptográfica na RAM, minimizando riscos de exposição por dump de memória.
* Botão **"Excluir"** no Vault para permitir a remoção de senhas salvas.

### Changed

* Cabeçalho de metadados agora utiliza versão explícita (`"v": 2`) para melhor controle e compatibilidade futura.
* Melhorada a segurança do arquivo criptografado com metadados autenticados através de AAD.
* Estrutura interna do arquivo `vault.enc` atualizada para incorporar segurança adicional e metadados explícitos (nonce determinístico e contador de gravações).

### Fixed

* Corrigido erro `AttributeError` relacionado ao uso inconsistente da variável de senha mestra (`self._password` para `self._pw`).
* Reintrodução correta dos atalhos de teclado:

  * <kbd>Ctrl + G</kbd>: Gerar nova senha.
  * <kbd>Ctrl + C</kbd>: Copiar senha.
  * <kbd>Ctrl + L</kbd>: Limpar senha e área de transferência.
  * <kbd>Esc</kbd>: Fechar aplicativo.

### Security

* Fortalecida a resistência a ataques de força bruta com parâmetros robustos do Argon2id (1 GiB RAM, 16 iterações).
* Proteção avançada contra ataques de replay ou manipulação do arquivo criptografado (nonce determinístico, contador e AAD).
* Melhoria na higiene de memória com zeroização explícita e tentativa de uso do `mlock` para fixação na memória física.

---

## \[1.1.0] – 2025‑05‑18

### Added

* **Botão “Limpar”** que apaga a senha exibida, zera a barra de força e limpa a área de transferência.
* Atalho de teclado <kbd>Ctrl + L</kbd> para o mesmo comportamento do botão.

### Changed

* O campo **Comprimento** agora aceita qualquer valor ≥ 1 (sem validação rígida no `Spinbox`).

### Removed

* Cópia automática da senha ao gerar: agora a senha só vai para a área de transferência quando o usuário clicar em **Copiar**.
* Janelas pop-up (`Messagebox`) de informação e erro, deixando a interface menos invasiva.

### Fixed

* O botão **Limpar** agora funciona corretamente: esvazia o clipboard, apaga o campo de senha, zera a barra de força e volta a ocultar a senha.

### Security

* Reduzido o tempo de exposição da senha na área de transferência ao exigir ação manual e oferecer função de limpeza.

---

## \[1.0.0] – 2025‑05‑17

### Added

* Primeira versão funcional com:

  * Gerador de senhas personalizável (comprimento, conjunto de caracteres).
  * Barra de força de senha.
  * Botões **Gerar**, **Copiar** e **Sair**.
  * Tema claro/escuro (Flatly / Superhero) com switch.
  * Salvamento opcional em arquivo de texto.
  * Atalhos de teclado básicos (<kbd>Ctrl + G</kbd>, <kbd>Ctrl + C</kbd>, <kbd>Esc</kbd>).

---

**Legend**

* *Added* – funcionalidade nova.
* *Changed* – alteração de funcionalidade existente.
* *Removed* – remoção de funcionalidade.
* *Fixed* – correção de bug.
* *Security* – mudanças que melhoram a segurança.
