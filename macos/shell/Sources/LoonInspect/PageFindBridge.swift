import Foundation

/// DOM discovery for the native find bar, in WebKit's isolated client world. No query or page text is sent to a provider.
enum PageFindBridge {
    static let install = #"""
    (() => {
      if (window.loonPageFind) return;
      let active = false, timer, revision = 0;
      const documentID = String(Date.now()) + ':' + Math.random();
      const visible = element => element && !element.disabled &&
        element.getClientRects().length > 0 && getComputedStyle(element).visibility !== 'hidden';
      const first = selector => Array.from(document.querySelectorAll(selector)).find(visible);
      const search = () => first('[data-page-search]');
      const ai = () => first('[data-page-ai-search]');
      const toggle = () => first('[data-page-ai-toggle]:not(:checked)');
      const focus = element => {
        if (!visible(element)) return false;
        element.scrollIntoView({block: 'center', behavior: 'instant'});
        element.focus({preventScroll: true});
        if (typeof element.select === 'function') element.select();
        return true;
      };
      window.loonPageFind = {
        activate(value) { active = value; },
        context() { return {page: location.href, document: documentID, revision, search: !!search(), ai: !!(ai() || toggle())}; },
        focus(kind) {
          if (kind === 'search') return focus(search());
          if (focus(ai())) return true;
          const lever = toggle();
          if (!lever || lever.checked) return false;
          // This is the same explicit mode choice as the page's AI checkbox. Never submit a question.
          lever.click();
          requestAnimationFrame(() => focus(ai()));
          return true;
        },
        selection() { return window.getSelection()?.toString().slice(0, 1024) || ''; }
      };
      new MutationObserver(() => {
        revision++;
        if (!active) return;
        clearTimeout(timer);
        timer = setTimeout(() => window.webkit.messageHandlers.pageFind.postMessage('changed'), 180);
      }).observe(document.documentElement, {
        subtree: true, childList: true, characterData: true, attributes: true,
        attributeFilter: ['hidden', 'aria-hidden', 'disabled', 'class', 'style',
                          'data-page-search', 'data-page-ai-search', 'data-page-ai-toggle']
      });
      window.webkit.messageHandlers.pageFind.postMessage('ready');
    })();
    """#
}
