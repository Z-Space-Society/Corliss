/* The only JavaScript in Corliss, and it is on /api/ for two reasons.
 *
 * This app is server-rendered with no client router; base.html argues at some
 * length for CSS over state-in-an-attribute, and the Quickstart tabs are hidden
 * radios for exactly that reason. Nothing here lays anything out. What is left
 * is the pair of things CSS cannot reach:
 *
 *   - the clipboard, on a page whose whole purpose is handing someone a string
 *     they are about to paste into a terminal;
 *   - putting a key the member already holds back into the examples, which is
 *     what makes the block complete on a visit that is not the one where the
 *     key was minted.
 *
 * Both are progressive. Every control this file drives is rendered `hidden` and
 * revealed here, so a browser without script — or without a clipboard, which is
 * any insecure context — shows no dead buttons. With the file blocked entirely
 * the page still tells you everything; you select the text yourself.
 *
 * **The pasted key is not persisted.** Not localStorage, not sessionStorage,
 * not a cookie. Corliss declines to store this secret server-side and the
 * argument does not get weaker for being in the member's own browser — the key
 * lives in their password manager or their shell, and a copy sitting in web
 * storage is the second copy the show-once design exists to avoid.
 */

(function () {
  "use strict";

  // How long "Copied" stands before the button says "Copy" again. Long enough
  // to be read as confirmation, short enough that the button is ready before
  // someone wants it a second time.
  var COPIED_MS = 1500;

  function setupCopyButtons() {
    // Not merely "is there a clipboard API" — it is absent in any insecure
    // context, so a plain-http deployment gets the no-JS page rather than
    // buttons that reject silently.
    if (!navigator.clipboard || !navigator.clipboard.writeText) {
      return;
    }

    var buttons = document.querySelectorAll("[data-copy]");
    Array.prototype.forEach.call(buttons, function (button) {
      var target = document.getElementById(button.getAttribute("data-copy"));
      if (!target) {
        return;
      }
      button.hidden = false;
      button.addEventListener("click", function () {
        // textContent, so what is copied is what is displayed: the export line
        // carries whatever the key slot currently holds, filled or placeholder.
        navigator.clipboard.writeText(target.textContent).then(
          function () {
            button.textContent = "Copied";
            button.classList.add("copy-btn--done");
            window.setTimeout(function () {
              button.textContent = "Copy";
              button.classList.remove("copy-btn--done");
            }, COPIED_MS);
          },
          function () {
            // A denied clipboard permission must not look like success. Say so
            // and leave it said — retrying would only be denied again.
            button.textContent = "Press ⌘C";
          }
        );
      });
    });
  }

  function setupKeyFill() {
    var panel = document.querySelector("[data-key-fill]");
    var slots = document.querySelectorAll("[data-key-slot]");
    if (!panel || !slots.length) {
      return;
    }

    var input = panel.querySelector("input");
    if (!input) {
      return;
    }

    // Whatever the server rendered — "sk-…" — is what an emptied field goes
    // back to. Read once, before anything has been typed over it.
    var placeholder = slots[0].textContent;

    panel.hidden = false;
    input.addEventListener("input", function () {
      var value = input.value.trim() || placeholder;
      Array.prototype.forEach.call(slots, function (slot) {
        // textContent, never innerHTML. A key is not markup and this is the
        // one place on the page where user-supplied text reaches the DOM.
        slot.textContent = value;
      });
    });
  }

  setupCopyButtons();
  setupKeyFill();
})();
