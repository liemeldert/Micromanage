import coreWebVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";
import jsxA11y from "eslint-plugin-jsx-a11y";

const eslintConfig = [{ignores: [".next/**", ".next.stale-*/**", "out/**", "node_modules/**", "next-env.d.ts"]}, ...coreWebVitals, ...nextTypescript, {
        rules: {
            ...jsxA11y.flatConfigs.recommended.rules,
            "jsx-a11y/no-autofocus": "off",
            "react-hooks/set-state-in-effect": "warn",
            "react-hooks/refs": "warn",
            "react-hooks/immutability": "warn",
            "react-hooks/purity": "warn",
            "react-hooks/static-components": "warn"
        }
    }];

export default eslintConfig;
