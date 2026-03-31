import type { UserConfig } from "@commitlint/types";

const config: UserConfig = {
  extends: ["@commitlint/config-conventional"],
  ignores: [
    (commit: string): boolean =>
      commit.startsWith("Merge") || commit.startsWith("Initial plan"),
  ],
  rules: {
    "header-max-length": [2, "always", 150],
    "body-max-line-length": [2, "always", 120],
    "footer-leading-blank": [0],
    "footer-max-line-length": [2, "always", 150],
  },
};

export default config;
