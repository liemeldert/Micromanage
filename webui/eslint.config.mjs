import {dirname} from "path";
import {fileURLToPath} from "url";
import {FlatCompat} from "@eslint/eslintrc";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const compat = new FlatCompat({
    baseDirectory: __dirname
});

const eslintConfig = [// Build output, including the .next.stale-* directories a dev server leaves
    // behind. `next lint` skipped these for us; `eslint .` has to be told.
    {ignores: [".next/**", ".next.stale-*/**", "out/**", "node_modules/**", "next-env.d.ts"]}, ...compat.extends("next/core-web-vitals", "next/typescript"), // next/core-web-vitals only turns on a handful of a11y rules; this is the
    // full recommended set, which is what catches a clickable row with no
    // keyboard path.
    ...compat.extends("plugin:jsx-a11y/recommended"), {
        rules: {
            // Every autofocus here follows an explicit user action (opening the
            // rename field, landing on the sign-in step) onto the one field that
            // step exists for.
            "jsx-a11y/no-autofocus": "off"
        }
    }];

export default eslintConfig;
