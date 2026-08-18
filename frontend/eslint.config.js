import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2022,
      globals: globals.browser
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": ["warn", { allowConstantExport: true }],

      // eslint-plugin-react-hooks v7 added these two rules, and they flag patterns
      // that predate them across several feature components. They are demoted to
      // warnings so CI can block on errors today rather than waiting on that
      // cleanup; see #15 before promoting them back to "error".
      "react-hooks/set-state-in-effect": "warn",
      "react-hooks/immutability": "warn"
    }
  }
);
