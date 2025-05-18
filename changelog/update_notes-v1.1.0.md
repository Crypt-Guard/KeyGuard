# Changelog

---

## \[1.1.0] – 2025‑05‑18

### Added

* **Botão “Limpar”** que apaga a senha exibida, zera a barra de força e limpa a área de transferência.
* Atalho de teclado <kbd>Ctrl + L</kbd> para o mesmo comportamento do botão.

### Changed

* O campo **Comprimento** agora aceita qualquer valor ≥ 1 (sem validação rígida no `Spinbox`).

### Removed

* Cópia automática da senha ao gerar: agora a senha só vai para a área de transferência quando o usuário clicar em **Copiar**.
* Janelas pop‑up (`Messagebox`) de informação e erro, deixando a interface menos invasiva.

### Fixed

* O botão **Limpar** agora funciona corretamente: esvazia o clipboard, apaga o campo de senha, zera a barra de força e volta a ocultar a senha.

### Security

* Reduzido o tempo de exposição da senha na área de transferência ao exigir ação manual e oferecer função de limpeza.

---

## \[1.0.0] – 2025‑05‑17

### Added

* Primeira versão funcional com:

  * Gerador de senhas personalizável (comprimento, conjunto de caracteres).
  * Barra de força de senha.
  * Botões **Gerar**, **Copiar** e **Sair**.
  * Tema claro/escuro (Flatly / Superhero) com switch.
  * Salvamento opcional em arquivo de texto.
  * Atalhos de teclado básicos (<kbd>Ctrl + G</kbd>, <kbd>Ctrl + C</kbd>, <kbd>Esc</kbd>).

---

**Legend**

* *Added* – funcionalidade nova.
* *Changed* – alteração de funcionalidade existente.
* *Removed* – remoção de funcionalidade.
* *Fixed* – correção de bug.
* *Security* – mudanças que melhoram a segurança.
