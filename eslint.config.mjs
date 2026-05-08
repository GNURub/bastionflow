import nextVitals from "eslint-config-next/core-web-vitals";
import nextTypescript from "eslint-config-next/typescript";

const eslintConfig = [
  ...nextVitals,
  ...nextTypescript,
  {
    rules: {
      // The dashboard fetches operational snapshots after mount/SSE setup.
      // This is an intentional client-side synchronization pattern, not derived state.
      "react-hooks/set-state-in-effect": "off"
    }
  }
];

export default eslintConfig;
